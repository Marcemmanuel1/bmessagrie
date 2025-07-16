const express = require("express");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const http = require("http");
const socketio = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = socketio(server, {
  cors: {
    origin: ["https://nexuchat.onrender.com", "http://127.0.0.1:5173"],
    methods: ["GET", "POST"],
    credentials: true,
  },
});

const PORT = 5000;
const JWT_SECRET = "votre_clé_secrète_jwt_très_complexe";
const JWT_EXPIRES_IN = "24h";

// Configuration de la base de données
const pool = mysql.createPool({
  host: "mysql-nexuchat.alwaysdata.net",
  user: "nexuchat",
  password: "Goldegelil@1",
  database: "nexuchat_messagerieapp",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Middlewares
app.use(
  cors({
    origin: ["https://nexuchat.onrender.com", "http://127.0.0.1:5173"],
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configuration des dossiers d'upload
const uploadsDir = path.join(__dirname, "uploads");
const avatarsDir = path.join(uploadsDir, "avatars");
const messagesDir = path.join(uploadsDir, "messages");

[uploadsDir, avatarsDir, messagesDir].forEach((dir) => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

app.use("/uploads/avatars", express.static(avatarsDir));
app.use("/uploads/messages", express.static(messagesDir));

// Configuration de Multer
const uploadAvatar = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, avatarsDir),
    filename: (req, file, cb) =>
      cb(null, `avatar-${Date.now()}${path.extname(file.originalname)}`),
  }),
  fileFilter: (req, file, cb) => {
    const allowed = ["image/jpeg", "image/png", "image/gif"];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error("Seuls JPEG, PNG et GIF sont autorisés."));
  },
  limits: { fileSize: 15 * 1024 * 1024 },
});

const uploadMessageFile = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, messagesDir),
    filename: (req, file, cb) => {
      const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
      cb(null, `msg-${uniqueSuffix}${path.extname(file.originalname)}`);
    },
  }),
  fileFilter: (req, file, cb) => {
    const allowed = [
      "image/jpeg",
      "image/png",
      "image/gif",
      "application/pdf",
      "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "application/vnd.ms-excel",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
      "application/vnd.ms-powerpoint",
      "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ];
    if (allowed.includes(file.mimetype)) cb(null, true);
    else cb(new Error("Type de fichier non autorisé"));
  },
  limits: { fileSize: 25 * 1024 * 1024 },
});

// Middleware d'authentification JWT
const requireAuth = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res
        .status(401)
        .json({ success: false, message: "Authentification requise" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const [user] = await pool.query(
      "SELECT id, name, email, avatar, status FROM users WHERE id = ?",
      [decoded.userId]
    );

    if (!user.length) {
      return res
        .status(401)
        .json({ success: false, message: "Utilisateur non trouvé" });
    }

    req.user = user[0];
    next();
  } catch (err) {
    console.error("Erreur vérification token:", err);
    res
      .status(401)
      .json({ success: false, message: "Token invalide ou expiré" });
  }
};

// Gestion des connexions Socket.io avec JWT
const onlineUsers = new Map();

io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) {
      return next(new Error("Authentification requise"));
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const [user] = await pool.query(
      "SELECT id, name, avatar, status FROM users WHERE id = ?",
      [decoded.userId]
    );

    if (!user.length) {
      return next(new Error("Utilisateur non trouvé"));
    }

    socket.user = user[0];
    next();
  } catch (err) {
    console.error("Erreur authentification socket:", err);
    next(new Error("Authentification échouée"));
  }
});

// Gestion des événements Socket.io
io.on("connection", async (socket) => {
  const userId = socket.user.id;

  // Mettre à jour le statut de l'utilisateur
  onlineUsers.set(userId, socket.id);
  await pool.query("UPDATE users SET status = 'En ligne' WHERE id = ?", [
    userId,
  ]);
  io.emit("user-status-changed", { userId, status: "En ligne" });

  // Gérer la déconnexion
  socket.on("disconnect", async () => {
    onlineUsers.delete(userId);
    await pool.query("UPDATE users SET status = 'Hors ligne' WHERE id = ?", [
      userId,
    ]);
    io.emit("user-status-changed", { userId, status: "Hors ligne" });
  });

  // Envoi de message
  socket.on(
    "send-message",
    async ({ conversationId, content, fileData }, callback) => {
      try {
        const conn = await pool.getConnection();

        try {
          await conn.beginTransaction();

          // Vérifier que l'utilisateur fait partie de la conversation
          const [conversation] = await conn.query(
            "SELECT user1_id, user2_id FROM conversations WHERE id = ?",
            [conversationId]
          );

          if (conversation.length === 0) {
            throw new Error("Conversation non trouvée");
          }

          const { user1_id, user2_id } = conversation[0];
          if (user1_id !== userId && user2_id !== userId) {
            throw new Error("Non autorisé");
          }

          // Insérer le message
          const messageContent = fileData ? JSON.stringify(fileData) : content;
          const [result] = await conn.query(
            "INSERT INTO messages (conversation_id, sender_id, content) VALUES (?, ?, ?)",
            [conversationId, userId, messageContent]
          );

          // Mettre à jour la conversation avec le dernier message
          await conn.query(
            "UPDATE conversations SET last_message_id = ? WHERE id = ?",
            [result.insertId, conversationId]
          );

          // Récupérer les détails complets du message
          const [message] = await conn.query(
            `
          SELECT m.id, m.content, m.created_at, m.sender_id, 
                 u.name as sender_name, u.avatar as sender_avatar,
                 u.status as sender_status
          FROM messages m
          JOIN users u ON m.sender_id = u.id
          WHERE m.id = ?
        `,
            [result.insertId]
          );

          await conn.commit();

          // Préparer les données du message pour l'émission
          const messageData = {
            ...message[0],
            conversationId,
            is_read: false,
          };

          // Parser le contenu JSON si c'est un fichier
          if (
            messageData.content &&
            messageData.content.startsWith("{") &&
            messageData.content.endsWith("}")
          ) {
            try {
              const fileData = JSON.parse(messageData.content);
              messageData.content = null;
              messageData.fileUrl = fileData.fileUrl;
              messageData.fileType = fileData.fileType;
            } catch (err) {
              console.error("Erreur parsing file data:", err);
            }
          }

          // Émettre le message aux participants de la conversation
          const otherUserId = user1_id === userId ? user2_id : user1_id;
          const recipientSocketId = onlineUsers.get(otherUserId);

          if (recipientSocketId) {
            io.to(recipientSocketId).emit("new-message", messageData);
            messageData.is_read = true;
          }

          // Émettre aussi à l'expéditeur pour confirmation
          socket.emit("message-sent", messageData);

          // Mettre à jour les conversations des deux utilisateurs
          const [updatedConv] = await conn.query(
            `
          SELECT c.id, 
                 CASE 
                   WHEN c.user1_id = ? THEN u2.id 
                   ELSE u1.id 
                 END as other_user_id,
                 CASE 
                   WHEN c.user1_id = ? THEN u2.name 
                   ELSE u1.name 
                 END as other_user_name,
                 CASE 
                   WHEN c.user1_id = ? THEN u2.avatar 
                   ELSE u1.avatar 
                 END as other_user_avatar,
                 CASE 
                   WHEN c.user1_id = ? THEN u2.status 
                   ELSE u1.status 
                 END as other_user_status,
                 m.content as last_message,
                 m.created_at as last_message_time,
                 (SELECT COUNT(*) FROM messages WHERE conversation_id = c.id AND sender_id != ? AND read_at IS NULL) as unread_count
          FROM conversations c
          JOIN users u1 ON c.user1_id = u1.id
          JOIN users u2 ON c.user2_id = u2.id
          LEFT JOIN messages m ON c.last_message_id = m.id
          WHERE c.id = ?
        `,
            [userId, userId, userId, userId, userId, conversationId]
          );

          if (updatedConv.length > 0) {
            const conversationUpdate = updatedConv[0];

            // Émettre la mise à jour de la conversation aux deux utilisateurs
            io.to(socket.id).emit("conversation-updated", conversationUpdate);
            if (recipientSocketId) {
              io.to(recipientSocketId).emit("conversation-updated", {
                ...conversationUpdate,
                unread_count: recipientSocketId
                  ? conversationUpdate.unread_count + 1
                  : 0,
              });
            }
          }

          callback({ success: true, message: messageData });
        } catch (err) {
          await conn.rollback();
          throw err;
        } finally {
          conn.release();
        }
      } catch (err) {
        console.error("Erreur envoi message via socket:", err);
        callback({
          success: false,
          message: "Erreur lors de l'envoi du message",
        });
      }
    }
  );

  // Marquer les messages comme lus
  socket.on("mark-as-read", async ({ conversationId }) => {
    try {
      await pool.query(
        "UPDATE messages SET read_at = NOW() WHERE conversation_id = ? AND sender_id != ? AND read_at IS NULL",
        [conversationId, userId]
      );

      // Mettre à jour la conversation avec le nouveau nombre de messages non lus
      const [conversation] = await pool.query(
        `
        SELECT c.id, 
               CASE 
                 WHEN c.user1_id = ? THEN u2.id 
                 ELSE u1.id 
               END as other_user_id,
               CASE 
                 WHEN c.user1_id = ? THEN u2.name 
                 ELSE u1.name 
               END as other_user_name,
               CASE 
                 WHEN c.user1_id = ? THEN u2.avatar 
                 ELSE u1.avatar 
               END as other_user_avatar,
               CASE 
                 WHEN c.user1_id = ? THEN u2.status 
                 ELSE u1.status 
               END as other_user_status,
               m.content as last_message,
               m.created_at as last_message_time,
               0 as unread_count
        FROM conversations c
        JOIN users u1 ON c.user1_id = u1.id
        JOIN users u2 ON c.user2_id = u2.id
        LEFT JOIN messages m ON c.last_message_id = m.id
        WHERE c.id = ?
      `,
        [userId, userId, userId, userId, conversationId]
      );

      if (conversation.length > 0) {
        socket.emit("conversation-updated", conversation[0]);

        // Informer l'autre utilisateur que ses messages ont été lus
        const otherUserId = conversation[0].other_user_id;
        const recipientSocketId = onlineUsers.get(otherUserId);
        if (recipientSocketId) {
          io.to(recipientSocketId).emit("messages-read", {
            conversationId,
            readerId: userId,
          });
        }
      }
    } catch (err) {
      console.error("Erreur marquage messages comme lus:", err);
    }
  });

  // Nouvel événement pour les nouvelles conversations
  socket.on("new-conversation-created", ({ conversationId }) => {
    // Diffuser à tous les utilisateurs concernés
    io.emit("conversation-created", { conversationId });
  });

  // Événement pour les appels vocaux/vidéo
  socket.on("call-user", ({ to, offer, callType }) => {
    const recipientSocketId = onlineUsers.get(to);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit("call-made", {
        from: userId,
        offer,
        callType,
        callerName: socket.user.name,
        callerAvatar: socket.user.avatar,
      });
    }
  });

  socket.on("answer-call", ({ to, answer }) => {
    const recipientSocketId = onlineUsers.get(to);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit("call-answered", {
        from: userId,
        answer,
      });
    }
  });

  socket.on("call-rejected", ({ to }) => {
    const recipientSocketId = onlineUsers.get(to);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit("call-rejected", {
        from: userId,
      });
    }
  });

  socket.on("end-call", ({ to }) => {
    const recipientSocketId = onlineUsers.get(to);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit("call-ended", {
        from: userId,
      });
    }
  });

  socket.on("ice-candidate", ({ to, candidate }) => {
    const recipientSocketId = onlineUsers.get(to);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit("ice-candidate", {
        from: userId,
        candidate,
      });
    }
  });

  socket.on(
    "send-group-message",
    async ({ groupId, content }, callback) => {
      try {
        const userId = socket.user.id;

        // Vérifier que l'utilisateur est membre du groupe
        const [isMember] = await pool.query(
          "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
          [groupId, userId]
        );

        if (isMember.length === 0) {
          throw new Error("Non autorisé");
        }

        const conn = await pool.getConnection();
        try {
          await conn.beginTransaction();

          // Insérer le message
          const [result] = await conn.query(
            "INSERT INTO group_messages (group_id, sender_id, content) VALUES (?, ?, ?)",
            [groupId, userId, content]
          );

          // Récupérer les détails complets du message
          const [message] = await conn.query(
            `
            SELECT gm.id, gm.content, gm.created_at, gm.sender_id, 
                   u.name as sender_name, u.avatar as sender_avatar
            FROM group_messages gm
            JOIN users u ON gm.sender_id = u.id
            WHERE gm.id = ?
          `,
            [result.insertId]
          );

          // Récupérer les membres du groupe
          const [members] = await conn.query(
            "SELECT user_id FROM group_members WHERE group_id = ?",
            [groupId]
          );

          await conn.commit();

          // Préparer les données du message pour l'émission
          const messageData = {
            ...message[0],
            groupId,
          };

          // Émettre le message aux membres du groupe
          members.forEach((member) => {
            const recipientSocketId = onlineUsers.get(member.user_id);
            if (recipientSocketId) {
              io.to(recipientSocketId).emit("new-group-message", messageData);
            }
          });

          callback({ success: true, message: messageData });
        } catch (err) {
          await conn.rollback();
          throw err;
        } finally {
          conn.release();
        }
      } catch (err) {
        console.error("Erreur envoi message groupe via socket:", err);
        callback({
          success: false,
          message: "Erreur lors de l'envoi du message",
        });
      }
    }
  );

  // Marquer les messages de groupe comme lus
  socket.on("mark-group-messages-as-read", async ({ groupId }) => {
    try {
      await pool.query(
        "UPDATE group_messages SET read_at = NOW() WHERE group_id = ? AND sender_id != ? AND read_at IS NULL",
        [groupId, socket.user.id]
      );

      // Mettre à jour le groupe avec le nouveau nombre de messages non lus
      const [group] = await pool.query(
        `
        SELECT g.id, g.name, g.description, g.created_by, 
               u.name as created_by_name, u.avatar as created_by_avatar,
               COUNT(gm.user_id) as member_count,
               (SELECT content FROM group_messages WHERE group_id = g.id ORDER BY created_at DESC LIMIT 1) as last_message,
               (SELECT created_at FROM group_messages WHERE group_id = g.id ORDER BY created_at DESC LIMIT 1) as last_message_time,
               0 as unread_count
        FROM groups g
        JOIN group_members gm ON g.id = gm.group_id
        JOIN users u ON g.created_by = u.id
        WHERE g.id = ? AND gm.user_id = ?
        GROUP BY g.id
      `,
        [groupId, socket.user.id]
      );

      if (group.length > 0) {
        socket.emit("group-updated", group[0]);
      }
    } catch (err) {
      console.error("Erreur marquage messages groupe comme lus:", err);
    }
  });
});

// Routes API
app.get("/api/check-auth", requireAuth, async (req, res) => {
  res.json({
    isAuthenticated: true,
    user: req.user,
  });
});

// Inscription
app.post("/api/register", uploadAvatar.single("avatar"), async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res
      .status(400)
      .json({ success: false, message: "Tous les champs sont requis" });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [existing] = await conn.query(
      "SELECT id FROM users WHERE email = ?",
      [email]
    );
    if (existing.length > 0) {
      if (req.file) fs.unlinkSync(req.file.path);
      return res
        .status(409)
        .json({ success: false, message: "Email déjà utilisé" });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const avatar = req.file
      ? `/uploads/avatars/${req.file.filename}`
      : "/uploads/avatars/default.jpg";

    const [result] = await conn.query(
      "INSERT INTO users (name, email, password, avatar, status, bio, phone, location) VALUES (?, ?, ?, ?, 'Hors ligne', '', '', '')",
      [name, email, hashedPassword, avatar]
    );

    const newUser = {
      id: result.insertId,
      name,
      email,
      avatar,
      status: "Hors ligne",
    };

    await conn.commit();

    // Créer le token JWT
    const token = jwt.sign({ userId: newUser.id }, JWT_SECRET, {
      expiresIn: JWT_EXPIRES_IN,
    });

    // Notifier tous les utilisateurs de la nouvelle inscription
    io.emit("new-user", newUser);

    res.status(201).json({
      success: true,
      message: "Inscription réussie",
      token,
      user: newUser,
    });
  } catch (err) {
    await conn.rollback();
    console.error("Erreur inscription:", err);
    if (req.file) fs.unlinkSync(req.file.path);
    res
      .status(500)
      .json({ success: false, message: "Erreur lors de l'inscription" });
  } finally {
    conn.release();
  }
});

// Connexion
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res
      .status(400)
      .json({ success: false, message: "Email et mot de passe requis" });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [rows] = await conn.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);
    if (rows.length === 0)
      return res
        .status(401)
        .json({ success: false, message: "Identifiants incorrects" });

    const user = rows[0];
    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass)
      return res
        .status(401)
        .json({ success: false, message: "Identifiants incorrects" });

    await conn.query("UPDATE users SET status = 'En ligne' WHERE id = ?", [
      user.id,
    ]);
    await conn.commit();

    // Créer le token JWT
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, {
      expiresIn: JWT_EXPIRES_IN,
    });

    const userData = {
      id: user.id,
      name: user.name,
      email: user.email,
      avatar: user.avatar,
      status: "En ligne",
    };

    // Notifier tous les utilisateurs du changement de statut
    io.emit("user-status-changed", { userId: user.id, status: "En ligne" });

    res.json({
      success: true,
      token,
      user: userData,
    });
  } catch (err) {
    await conn.rollback();
    console.error("Erreur connexion:", err);
    res
      .status(500)
      .json({ success: false, message: "Erreur lors de la connexion" });
  } finally {
    conn.release();
  }
});

// Déconnexion
app.post("/api/logout", requireAuth, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    await conn.query("UPDATE users SET status = 'Hors ligne' WHERE id = ?", [
      req.user.id,
    ]);
    await conn.commit();

    // Notifier tous les utilisateurs du changement de statut
    io.emit("user-status-changed", {
      userId: req.user.id,
      status: "Hors ligne",
    });

    res.json({ success: true, message: "Déconnexion réussie" });
  } catch (err) {
    await conn.rollback();
    res
      .status(500)
      .json({ success: false, message: "Erreur lors de la déconnexion" });
  } finally {
    conn.release();
  }
});
app.post("/api/groups", requireAuth, async (req, res) => {
  const { name, description, members } = req.body;
  const userId = req.user.id;

  if (!name || !members || !Array.isArray(members)) {
    return res.status(400).json({
      success: false,
      message: "Nom du groupe et membres sont requis",
    });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Créer le groupe
    const [groupResult] = await conn.query(
      "INSERT INTO groups (name, description, created_by) VALUES (?, ?, ?)",
      [name, description || null, userId]
    );

    const groupId = groupResult.insertId;

    // Ajouter le créateur comme admin
    await conn.query(
      "INSERT INTO group_members (group_id, user_id, is_admin) VALUES (?, ?, TRUE)",
      [groupId, userId]
    );

    // Ajouter les autres membres
    const membersToAdd = members.filter((m) => m !== userId);
    if (membersToAdd.length > 0) {
      const values = membersToAdd.map((memberId) => [groupId, memberId]);
      await conn.query(
        "INSERT INTO group_members (group_id, user_id) VALUES ?",
        [values]
      );
    }

    // Récupérer les détails complets du groupe
    const [group] = await conn.query(
      `
      SELECT g.id, g.name, g.description, g.created_by, 
             u.name as created_by_name, u.avatar as created_by_avatar,
             COUNT(gm.user_id) as member_count
      FROM groups g
      JOIN users u ON g.created_by = u.id
      LEFT JOIN group_members gm ON g.id = gm.group_id
      WHERE g.id = ?
      GROUP BY g.id
    `,
      [groupId]
    );

    await conn.commit();

    // Notifier les membres du nouveau groupe
    const allMembers = [...membersToAdd, userId];
    allMembers.forEach((memberId) => {
      const socketId = onlineUsers.get(memberId);
      if (socketId) {
        io.to(socketId).emit("new-group", group[0]);
      }
    });

    res.json({ success: true, group: group[0] });
  } catch (err) {
    await conn.rollback();
    console.error("Erreur création groupe:", err);
    res.status(500).json({
      success: false,
      message: "Erreur lors de la création du groupe",
    });
  } finally {
    conn.release();
  }
});

// Lister les groupes d'un utilisateur
app.get("/api/groups", requireAuth, async (req, res) => {
  try {
    const [groups] = await pool.query(
      `
      SELECT g.id, g.name, g.description, g.created_by, 
             u.name as created_by_name, u.avatar as created_by_avatar,
             COUNT(gm.user_id) as member_count,
             (SELECT content FROM group_messages WHERE group_id = g.id ORDER BY created_at DESC LIMIT 1) as last_message,
             (SELECT created_at FROM group_messages WHERE group_id = g.id ORDER BY created_at DESC LIMIT 1) as last_message_time,
             (SELECT COUNT(*) FROM group_messages WHERE group_id = g.id AND sender_id != ? AND read_at IS NULL) as unread_count
      FROM groups g
      JOIN group_members gm ON g.id = gm.group_id
      JOIN users u ON g.created_by = u.id
      WHERE gm.user_id = ?
      GROUP BY g.id
      ORDER BY last_message_time DESC
    `,
      [req.user.id, req.user.id]
    );

    res.json({ success: true, groups });
  } catch (err) {
    console.error("Erreur liste groupes:", err);
    res.status(500).json({ success: false, message: "Erreur serveur" });
  }
});

// Obtenir les détails d'un groupe
app.get("/api/groups/:groupId", requireAuth, async (req, res) => {
  try {
    const [group] = await pool.query(
      `
      SELECT g.id, g.name, g.description, g.created_by, 
             u.name as created_by_name, u.avatar as created_by_avatar,
             COUNT(gm.user_id) as member_count,
             MAX(gm.is_admin = 1 AND gm.user_id = ?) as is_admin
      FROM groups g
      JOIN group_members gm ON g.id = gm.group_id
      JOIN users u ON g.created_by = u.id
      WHERE g.id = ? AND gm.user_id = ?
      GROUP BY g.id
    `,
      [req.user.id, req.params.groupId, req.user.id]
    );

    if (group.length === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Groupe non trouvé ou accès refusé" });
    }

    // Récupérer les membres
    const [members] = await pool.query(
      `
      SELECT u.id, u.name, u.avatar, u.status, gm.is_admin
      FROM group_members gm
      JOIN users u ON gm.user_id = u.id
      WHERE gm.group_id = ?
      ORDER BY gm.is_admin DESC, u.name ASC
    `,
      [req.params.groupId]
    );

    res.json({
      success: true,
      group: { ...group[0], members },
    });
  } catch (err) {
    console.error("Erreur détails groupe:", err);
    res.status(500).json({ success: false, message: "Erreur serveur" });
  }
});

// Quitter un groupe
app.post("/api/groups/:groupId/leave", requireAuth, async (req, res) => {
  try {
    const groupId = req.params.groupId;
    const userId = req.user.id;

    // Vérifier si l'utilisateur est le créateur
    const [group] = await pool.query(
      "SELECT created_by FROM groups WHERE id = ?",
      [groupId]
    );

    if (group.length === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Groupe non trouvé" });
    }

    if (group[0].created_by === userId) {
      return res.status(400).json({
        success: false,
        message: "Le créateur ne peut pas quitter le groupe. Supprimez-le à la place.",
      });
    }

    // Supprimer l'utilisateur du groupe
    await pool.query(
      "DELETE FROM group_members WHERE group_id = ? AND user_id = ?",
      [groupId, userId]
    );

    // Notifier les autres membres
    const [members] = await pool.query(
      "SELECT user_id FROM group_members WHERE group_id = ?",
      [groupId]
    );

    members.forEach((member) => {
      const socketId = onlineUsers.get(member.user_id);
      if (socketId) {
        io.to(socketId).emit("group-member-left", {
          groupId,
          userId,
        });
      }
    });

    res.json({ success: true, message: "Vous avez quitté le groupe" });
  } catch (err) {
    console.error("Erreur quitter groupe:", err);
    res.status(500).json({ success: false, message: "Erreur serveur" });
  }
});

// Supprimer un groupe
app.delete("/api/groups/:groupId", requireAuth, async (req, res) => {
  try {
    const groupId = req.params.groupId;
    const userId = req.user.id;

    // Vérifier si l'utilisateur est le créateur
    const [group] = await pool.query(
      "SELECT created_by FROM groups WHERE id = ?",
      [groupId]
    );

    if (group.length === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Groupe non trouvé" });
    }

    if (group[0].created_by !== userId) {
      return res.status(403).json({
        success: false,
        message: "Seul le créateur peut supprimer le groupe",
      });
    }

    // Supprimer le groupe (les contraintes de clé étrangère supprimeront les membres et messages)
    await pool.query("DELETE FROM groups WHERE id = ?", [groupId]);

    // Notifier tous les membres
    const [members] = await pool.query(
      "SELECT user_id FROM group_members WHERE group_id = ?",
      [groupId]
    );

    members.forEach((member) => {
      const socketId = onlineUsers.get(member.user_id);
      if (socketId) {
        io.to(socketId).emit("group-deleted", { groupId });
      }
    });

    res.json({ success: true, message: "Groupe supprimé avec succès" });
  } catch (err) {
    console.error("Erreur suppression groupe:", err);
    res.status(500).json({ success: false, message: "Erreur serveur" });
  }
});

// Ajouter des membres à un groupe
app.post("/api/groups/:groupId/members", requireAuth, async (req, res) => {
  const { members } = req.body;
  const groupId = req.params.groupId;
  const userId = req.user.id;

  if (!members || !Array.isArray(members)) {
    return res
      .status(400)
      .json({ success: false, message: "Liste des membres requise" });
  }

  // Vérifier si l'utilisateur est admin du groupe
  const [isAdmin] = await pool.query(
    "SELECT is_admin FROM group_members WHERE group_id = ? AND user_id = ?",
    [groupId, userId]
  );

  if (isAdmin.length === 0 || !isAdmin[0].is_admin) {
    return res.status(403).json({
      success: false,
      message: "Seuls les administrateurs peuvent ajouter des membres",
    });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Filtrer les membres déjà dans le groupe
    const [existingMembers] = await conn.query(
      "SELECT user_id FROM group_members WHERE group_id = ? AND user_id IN (?)",
      [groupId, members]
    );

    const existingMemberIds = existingMembers.map((m) => m.user_id);
    const newMembers = members.filter((m) => !existingMemberIds.includes(m));

    if (newMembers.length > 0) {
      const values = newMembers.map((memberId) => [groupId, memberId]);
      await conn.query(
        "INSERT INTO group_members (group_id, user_id) VALUES ?",
        [values]
      );
    }

    // Récupérer les détails des nouveaux membres
    const [addedMembers] = await conn.query(
      "SELECT id, name, avatar, status FROM users WHERE id IN (?)",
      [newMembers]
    );

    await conn.commit();

    // Notifier tous les membres du groupe
    const [allMembers] = await conn.query(
      "SELECT user_id FROM group_members WHERE group_id = ?",
      [groupId]
    );

    allMembers.forEach((member) => {
      const socketId = onlineUsers.get(member.user_id);
      if (socketId) {
        io.to(socketId).emit("group-members-added", {
          groupId,
          members: addedMembers,
        });
      }
    });

    // Notifier les nouveaux membres
    newMembers.forEach((memberId) => {
      const socketId = onlineUsers.get(memberId);
      if (socketId) {
        io.to(socketId).emit("added-to-group", { groupId });
      }
    });

    res.json({
      success: true,
      message: "Membres ajoutés avec succès",
      addedMembers,
    });
  } catch (err) {
    await conn.rollback();
    console.error("Erreur ajout membres:", err);
    res.status(500).json({
      success: false,
      message: "Erreur lors de l'ajout des membres",
    });
  } finally {
    conn.release();
  }
});

// Supprimer un membre d'un groupe
app.delete(
  "/api/groups/:groupId/members/:memberId",
  requireAuth,
  async (req, res) => {
    try {
      const { groupId, memberId } = req.params;
      const userId = req.user.id;

      // Vérifier si l'utilisateur est admin ou s'il se supprime lui-même
      const [isAdmin] = await pool.query(
        "SELECT is_admin FROM group_members WHERE group_id = ? AND user_id = ?",
        [groupId, userId]
      );

      if (isAdmin.length === 0) {
        return res.status(403).json({
          success: false,
          message: "Vous n'êtes pas membre de ce groupe",
        });
      }

      if (memberId !== userId && !isAdmin[0].is_admin) {
        return res.status(403).json({
          success: false,
          message: "Seuls les administrateurs peuvent supprimer des membres",
        });
      }

      // Vérifier si le membre à supprimer est le créateur
      const [group] = await pool.query(
        "SELECT created_by FROM groups WHERE id = ?",
        [groupId]
      );

      if (group.length > 0 && group[0].created_by == memberId) {
        return res.status(400).json({
          success: false,
          message: "Le créateur ne peut pas être supprimé du groupe",
        });
      }

      // Supprimer le membre
      await pool.query(
        "DELETE FROM group_members WHERE group_id = ? AND user_id = ?",
        [groupId, memberId]
      );

      // Notifier tous les membres du groupe
      const [members] = await pool.query(
        "SELECT user_id FROM group_members WHERE group_id = ?",
        [groupId]
      );

      members.forEach((member) => {
        const socketId = onlineUsers.get(member.user_id);
        if (socketId) {
          io.to(socketId).emit("group-member-removed", {
            groupId,
            memberId,
          });
        }
      });

      // Notifier le membre supprimé
      const removedSocketId = onlineUsers.get(memberId);
      if (removedSocketId) {
        io.to(removedSocketId).emit("removed-from-group", { groupId });
      }

      res.json({ success: true, message: "Membre supprimé du groupe" });
    } catch (err) {
      console.error("Erreur suppression membre:", err);
      res.status(500).json({ success: false, message: "Erreur serveur" });
    }
  }
);

// Messages de groupe
app.get("/api/groups/:groupId/messages", requireAuth, async (req, res) => {
  try {
    const groupId = req.params.groupId;
    const userId = req.user.id;

    // Vérifier que l'utilisateur est membre du groupe
    const [isMember] = await pool.query(
      "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
      [groupId, userId]
    );

    if (isMember.length === 0) {
      return res
        .status(403)
        .json({ success: false, message: "Accès refusé" });
    }

    const [messages] = await pool.query(
      `
      SELECT gm.id, gm.content, gm.created_at, gm.sender_id, 
             u.name as sender_name, u.avatar as sender_avatar
      FROM group_messages gm
      JOIN users u ON gm.sender_id = u.id
      WHERE gm.group_id = ?
      ORDER BY gm.created_at ASC
    `,
      [groupId]
    );

    // Marquer les messages comme lus
    await pool.query(
      "UPDATE group_messages SET read_at = NOW() WHERE group_id = ? AND sender_id != ? AND read_at IS NULL",
      [groupId, userId]
    );

    res.json({ success: true, messages });
  } catch (err) {
    console.error("Erreur récupération messages groupe:", err);
    res.status(500).json({ success: false, message: "Erreur serveur" });
  }
});

// Envoyer un message dans un groupe
app.post("/api/groups/:groupId/messages", requireAuth, async (req, res) => {
  try {
    const groupId = req.params.groupId;
    const { content } = req.body;
    const userId = req.user.id;

    if (!content) {
      return res
        .status(400)
        .json({ success: false, message: "Contenu du message requis" });
    }

    // Vérifier que l'utilisateur est membre du groupe
    const [isMember] = await pool.query(
      "SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?",
      [groupId, userId]
    );

    if (isMember.length === 0) {
      return res
        .status(403)
        .json({ success: false, message: "Accès refusé" });
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // Insérer le message
      const [result] = await conn.query(
        "INSERT INTO group_messages (group_id, sender_id, content) VALUES (?, ?, ?)",
        [groupId, userId, content]
      );

      // Récupérer les détails complets du message
      const [message] = await conn.query(
        `
        SELECT gm.id, gm.content, gm.created_at, gm.sender_id, 
               u.name as sender_name, u.avatar as sender_avatar
        FROM group_messages gm
        JOIN users u ON gm.sender_id = u.id
        WHERE gm.id = ?
      `,
        [result.insertId]
      );

      // Récupérer les membres du groupe (sauf l'expéditeur)
      const [members] = await conn.query(
        "SELECT user_id FROM group_members WHERE group_id = ? AND user_id != ?",
        [groupId, userId]
      );

      await conn.commit();

      // Émettre le message aux membres du groupe via Socket.io
      const messageData = {
        ...message[0],
        groupId,
      };

      members.forEach((member) => {
        const socketId = onlineUsers.get(member.user_id);
        if (socketId) {
          io.to(socketId).emit("new-group-message", messageData);
        }
      });

      res.json({ success: true, message: messageData });
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error("Erreur envoi message groupe:", err);
    res.status(500).json({ success: false, message: "Erreur serveur" });
  }
});

// Liste des utilisateurs
app.get("/api/users", requireAuth, async (req, res) => {
  try {
    const [users] = await pool.query(
      "SELECT id, name, avatar, status, bio, phone, location FROM users WHERE id != ? ORDER BY name ASC",
      [req.user.id]
    );

    res.json({ success: true, users });
  } catch (err) {
    console.error("Erreur liste utilisateurs:", err);
    res.status(500).json({ success: false, message: "Erreur serveur" });
  }
});

// Profil utilisateur
app.get("/api/profile", requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.query(
      "SELECT id, name, email, avatar, status, bio, phone, location FROM users WHERE id = ?",
      [req.user.id]
    );

    if (rows.length === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Utilisateur non trouvé" });
    }

    const user = rows[0];
    res.json({ success: true, user });
  } catch (err) {
    console.error("Erreur récupération profil:", err);
    res.status(500).json({ success: false, message: "Erreur serveur" });
  }
});

// Mise à jour du profil
app.put(
  "/api/profile",
  requireAuth,
  uploadAvatar.single("avatar"),
  async (req, res) => {
    const { name, bio, phone, location } = req.body;
    const userId = req.user.id;

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      let avatar = req.user.avatar;
      if (req.file) {
        avatar = `/uploads/avatars/${req.file.filename}`;
        if (req.user.avatar !== "/uploads/avatars/default.jpg") {
          const oldAvatarPath = path.join(__dirname, req.user.avatar);
          if (fs.existsSync(oldAvatarPath)) fs.unlinkSync(oldAvatarPath);
        }
      }

      await conn.query(
        "UPDATE users SET name = ?, bio = ?, phone = ?, location = ?, avatar = ? WHERE id = ?",
        [name, bio, phone, location, avatar, userId]
      );

      const updatedUser = {
        id: userId,
        name,
        email: req.user.email,
        avatar,
        status: req.user.status,
        bio,
        phone,
        location,
      };

      await conn.commit();

      // Notifier tous les utilisateurs de la mise à jour du profil
      io.emit("user-updated", updatedUser);

      res.json({
        success: true,
        user: updatedUser,
      });
    } catch (err) {
      await conn.rollback();
      console.error("Erreur mise à jour profil:", err);
      if (req.file) fs.unlinkSync(req.file.path);
      res
        .status(500)
        .json({
          success: false,
          message: "Erreur lors de la mise à jour du profil",
        });
    } finally {
      conn.release();
    }
  }
);

// Liste des conversations
app.get("/api/conversations", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;

    const [conversations] = await pool.query(
      `
      SELECT c.id, 
             CASE 
               WHEN c.user1_id = ? THEN u2.id 
               ELSE u1.id 
             END as other_user_id,
             CASE 
               WHEN c.user1_id = ? THEN u2.name 
               ELSE u1.name 
             END as other_user_name,
             CASE 
               WHEN c.user1_id = ? THEN u2.avatar 
               ELSE u1.avatar 
             END as other_user_avatar,
             CASE 
               WHEN c.user1_id = ? THEN u2.status 
               ELSE u1.status 
             END as other_user_status,
             m.content as last_message,
             m.created_at as last_message_time,
             (SELECT COUNT(*) FROM messages WHERE conversation_id = c.id AND sender_id != ? AND read_at IS NULL) as unread_count
      FROM conversations c
      JOIN users u1 ON c.user1_id = u1.id
      JOIN users u2 ON c.user2_id = u2.id
      LEFT JOIN messages m ON c.last_message_id = m.id
      WHERE c.user1_id = ? OR c.user2_id = ?
      ORDER BY m.created_at DESC
    `,
      [userId, userId, userId, userId, userId, userId, userId]
    );

    res.json({ success: true, conversations });
  } catch (err) {
    console.error("Erreur récupération conversations:", err);
    res.status(500).json({ success: false, message: "Erreur serveur" });
  }
});

// Récupérer ou créer une conversation (version optimisée)
// Récupérer ou créer une conversation (version optimisée)
app.get("/api/conversations/:otherUserId", requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const otherUserId = req.params.otherUserId;

    // Vérifier si la conversation existe déjà
    const [existing] = await pool.query(
      `SELECT id FROM conversations 
       WHERE (user1_id = ? AND user2_id = ?) 
          OR (user1_id = ? AND user2_id = ?)`,
      [userId, otherUserId, otherUserId, userId]
    );

    if (existing.length > 0) {
      // Si la conversation existe, retourner l'ID
      return res.json({ success: true, conversationId: existing[0].id });
    }

    // Créer une nouvelle conversation
    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      
      // Insérer la nouvelle conversation
      const [result] = await conn.query(
        "INSERT INTO conversations (user1_id, user2_id) VALUES (?, ?)",
        [userId, otherUserId]
      );

      // Récupérer les détails complets de la nouvelle conversation
      const [newConversation] = await conn.query(
        `
        SELECT c.id, 
               CASE 
                 WHEN c.user1_id = ? THEN u2.id 
                 ELSE u1.id 
               END as other_user_id,
               CASE 
                 WHEN c.user1_id = ? THEN u2.name 
                 ELSE u1.name 
               END as other_user_name,
               CASE 
                 WHEN c.user1_id = ? THEN u2.avatar 
                 ELSE u1.avatar 
               END as other_user_avatar,
               CASE 
                 WHEN c.user1_id = ? THEN u2.status 
                 ELSE u1.status 
               END as other_user_status,
               NULL as last_message,
               NULL as last_message_time,
               0 as unread_count
        FROM conversations c
        JOIN users u1 ON c.user1_id = u1.id
        JOIN users u2 ON c.user2_id = u2.id
        WHERE c.id = ?
      `,
        [userId, userId, userId, userId, result.insertId]
      );

      await conn.commit();

      const conversationData = newConversation[0];
      
      // Format standardisé pour l'émission
      const conversationPayload = {
        id: conversationData.id,
        other_user_id: conversationData.other_user_id,
        other_user_name: conversationData.other_user_name,
        other_user_avatar: conversationData.other_user_avatar,
        other_user_status: conversationData.other_user_status,
        last_message: null,
        last_message_time: new Date().toISOString(),
        unread_count: 0,
        isNew: true // Nouvelle propriété pour l'indicateur visuel
      };

      // Émettre à l'initiateur
      const initiatorSocketId = onlineUsers.get(userId);
      if (initiatorSocketId) {
        io.to(initiatorSocketId).emit('new-conversation', conversationPayload);
      }

      // Émettre à l'autre utilisateur (avec ses propres données)
      const otherUserSocketId = onlineUsers.get(otherUserId);
      if (otherUserSocketId) {
        // Récupérer les infos de l'initiateur pour l'autre utilisateur
        const [initiator] = await pool.query(
          "SELECT id, name, avatar, status FROM users WHERE id = ?",
          [userId]
        );
        
        if (initiator.length > 0) {
          io.to(otherUserSocketId).emit('new-conversation', {
            id: conversationData.id,
            other_user_id: initiator[0].id,
            other_user_name: initiator[0].name,
            other_user_avatar: initiator[0].avatar,
            other_user_status: initiator[0].status,
            last_message: null,
            last_message_time: new Date().toISOString(),
            unread_count: 0,
            isNew: true
          });
        }
      }

      res.json({ 
        success: true, 
        conversationId: result.insertId,
        conversation: conversationPayload
      });

    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error("Erreur récupération/conversation:", err);
    res.status(500).json({ 
      success: false, 
      message: "Erreur serveur",
      error: err.message 
    });
  }
});

// Récupérer les messages d'une conversation
app.get("/api/messages/:conversationId", requireAuth, async (req, res) => {
  try {
    const conversationId = req.params.conversationId;
    const userId = req.user.id;

    const [messages] = await pool.query(
      `
      SELECT 
        m.id, 
        m.conversation_id,
        m.content, 
        m.created_at, 
        m.sender_id, 
        u.name as sender_name, 
        u.avatar as sender_avatar,
        m.read_at IS NOT NULL as is_read
      FROM messages m
      JOIN users u ON m.sender_id = u.id
      WHERE m.conversation_id = ?
      ORDER BY m.created_at ASC
    `,
      [conversationId]
    );

    // Parser le contenu JSON pour les messages avec fichiers
    const parsedMessages = messages.map((msg) => {
      try {
        const content = msg.content;
        if (content && content.startsWith("{") && content.endsWith("}")) {
          const fileData = JSON.parse(content);
          return {
            ...msg,
            content: null,
            fileUrl: fileData.fileUrl,
            fileType: fileData.fileType,
          };
        }
        return msg;
      } catch (err) {
        return msg;
      }
    });

    // Marquer les messages comme lus
    await pool.query(
      "UPDATE messages SET read_at = NOW() WHERE conversation_id = ? AND sender_id != ? AND read_at IS NULL",
      [conversationId, userId]
    );

    res.json({ success: true, messages: parsedMessages });
  } catch (err) {
    console.error("Erreur récupération messages:", err);
    res.status(500).json({ success: false, message: "Erreur serveur" });
  }
});




// Upload de fichiers pour les messages
app.post(
  "/api/messages/upload",
  requireAuth,
  uploadMessageFile.single("file"),
  async (req, res) => {
    if (!req.file) {
      return res
        .status(400)
        .json({ success: false, message: "Aucun fichier fourni" });
    }

    const { conversationId } = req.body;
    const userId = req.user.id;
    const fileUrl = `/uploads/messages/${req.file.filename}`;
    const fileType = req.file.mimetype;

    // Stocker le chemin du fichier dans le contenu du message
    const content = JSON.stringify({ fileUrl, fileType });

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // Vérifier que l'utilisateur fait partie de la conversation
      const [conversation] = await conn.query(
        "SELECT user1_id, user2_id FROM conversations WHERE id = ? AND (user1_id = ? OR user2_id = ?)",
        [conversationId, userId, userId]
      );

      if (conversation.length === 0) {
        fs.unlinkSync(req.file.path);
        return res
          .status(403)
          .json({ success: false, message: "Non autorisé" });
      }

      const { user1_id, user2_id } = conversation[0];
      const otherUserId = user1_id === userId ? user2_id : user1_id;

      // Insérer le message
      const [result] = await conn.query(
        "INSERT INTO messages (conversation_id, sender_id, content) VALUES (?, ?, ?)",
        [conversationId, userId, content]
      );

      // Mettre à jour la conversation avec le dernier message
      await conn.query(
        "UPDATE conversations SET last_message_id = ? WHERE id = ?",
        [result.insertId, conversationId]
      );

      // Récupérer les détails complets du message
      const [message] = await conn.query(
        `
      SELECT m.id, m.content, m.created_at, m.sender_id, 
             u.name as sender_name, u.avatar as sender_avatar,
             u.status as sender_status
      FROM messages m
      JOIN users u ON m.sender_id = u.id
      WHERE m.id = ?
    `,
        [result.insertId]
      );

      await conn.commit();

      // Préparer les données du message pour l'émission
      const messageData = {
        ...message[0],
        content: null,
        fileUrl,
        fileType,
        conversationId,
        is_read: false,
      };

      // Émettre le message via Socket.io
      const recipientSocketId = onlineUsers.get(otherUserId);
      if (recipientSocketId) {
        io.to(recipientSocketId).emit("new-message", messageData);
        messageData.is_read = true;
      }

      // Émettre aussi à l'expéditeur pour confirmation
      const senderSocketId = onlineUsers.get(userId);
      if (senderSocketId) {
        io.to(senderSocketId).emit("message-sent", messageData);
      }

      // Mettre à jour les conversations des deux utilisateurs
      const [updatedConv] = await conn.query(
        `
      SELECT c.id, 
             CASE 
               WHEN c.user1_id = ? THEN u2.id 
               ELSE u1.id 
             END as other_user_id,
             CASE 
               WHEN c.user1_id = ? THEN u2.name 
               ELSE u1.name 
             END as other_user_name,
             CASE 
               WHEN c.user1_id = ? THEN u2.avatar 
               ELSE u1.avatar 
             END as other_user_avatar,
             CASE 
               WHEN c.user1_id = ? THEN u2.status 
               ELSE u1.status 
             END as other_user_status,
             m.content as last_message,
             m.created_at as last_message_time,
             (SELECT COUNT(*) FROM messages WHERE conversation_id = c.id AND sender_id != ? AND read_at IS NULL) as unread_count
      FROM conversations c
      JOIN users u1 ON c.user1_id = u1.id
      JOIN users u2 ON c.user2_id = u2.id
      LEFT JOIN messages m ON c.last_message_id = m.id
      WHERE c.id = ?
    `,
        [userId, userId, userId, userId, userId, conversationId]
      );

      if (updatedConv.length > 0) {
        const conversationUpdate = updatedConv[0];

        // Émettre la mise à jour de la conversation aux deux utilisateurs
        if (senderSocketId) {
          io.to(senderSocketId).emit(
            "conversation-updated",
            conversationUpdate
          );
        }
        if (recipientSocketId) {
          io.to(recipientSocketId).emit("conversation-updated", {
            ...conversationUpdate,
            unread_count: recipientSocketId
              ? conversationUpdate.unread_count + 1
              : 0,
          });
        }
      }

      res.json({
        success: true,
        message: messageData,
      });
    } catch (err) {
      await conn.rollback();
      if (req.file) fs.unlinkSync(req.file.path);
      console.error("Erreur upload fichier:", err);
      res
        .status(500)
        .json({ success: false, message: "Erreur lors de l'envoi du fichier" });
    } finally {
      conn.release();
    }
  }
);

// Démarrer le serveur
server.listen(PORT, () => {
  console.log(`Serveur démarré sur http://localhost:${PORT}`);
});

// Gestion des erreurs non capturées
process.on("unhandledRejection", (err) => {
  console.error("Unhandled Rejection:", err);
});

process.on("uncaughtException", (err) => {
  console.error("Uncaught Exception:", err);
});