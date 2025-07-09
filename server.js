require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const http = require('http');
const socketio = require('socket.io');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { v4: uuidv4 } = require('uuid');
const mime = require('mime-types');

// Initialisation
const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || uuidv4();
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '24h';

// Configuration Socket.io
const io = socketio(server, {
  cors: {
    origin: process.env.ALLOWED_ORIGINS?.split(',') || [
      'http://localhost:5173',
      'https://yourproductiondomain.com'
    ],
    methods: ['GET', 'POST'],
    credentials: true
  },
  transports: ['websocket', 'polling'],
  pingTimeout: 60000,
  pingInterval: 25000
});

// Middlewares de sécurité
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || [
    'http://localhost:5173',
    'https://yourproductiondomain.com'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));

// Rate limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false
});
app.use('/api/', apiLimiter);

// Configuration de la base de données
const pool = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'messenger',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  timezone: 'local'
});

// Initialisation des dossiers
const initDirectories = () => {
  const uploadsDir = path.join(__dirname, 'uploads');
  const avatarsDir = path.join(uploadsDir, 'avatars');
  const messagesDir = path.join(uploadsDir, 'messages');

  [uploadsDir, avatarsDir, messagesDir].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  });

  // Créer un avatar par défaut si inexistant
  const defaultAvatarPath = path.join(avatarsDir, 'default.jpg');
  if (!fs.existsSync(defaultAvatarPath)) {
    fs.copyFileSync(path.join(__dirname, 'assets/default-avatar.jpg'), defaultAvatarPath);
  }

  return { avatarsDir, messagesDir };
};

const { avatarsDir, messagesDir } = initDirectories();
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Configuration Multer
const fileFilter = (allowedTypes) => (req, file, cb) => {
  const isValid = allowedTypes.includes(mime.lookup(file.originalname));
  cb(null, isValid);
};

const avatarStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, avatarsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `avatar-${uuidv4()}${ext}`);
  }
});

const messageFileStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, messagesDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `msg-${uuidv4()}${ext}`);
  }
});

const uploadAvatar = multer({
  storage: avatarStorage,
  fileFilter: fileFilter(['image/jpeg', 'image/png', 'image/gif']),
  limits: { fileSize: 15 * 1024 * 1024 }
});

const uploadMessageFile = multer({
  storage: messageFileStorage,
  fileFilter: fileFilter([
    'image/jpeg', 'image/png', 'image/gif',
    'application/pdf',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/vnd.ms-powerpoint',
    'application/vnd.openxmlformats-officedocument.presentationml.presentation'
  ]),
  limits: { fileSize: 25 * 1024 * 1024 }
});

// Middleware d'authentification
const authenticate = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ success: false, message: "Authentification requise" });

    const decoded = jwt.verify(token, JWT_SECRET);
    const [user] = await pool.execute(
      "SELECT id, name, email, avatar, status FROM users WHERE id = ?", 
      [decoded.userId]
    );
    
    if (!user.length) return res.status(401).json({ success: false, message: "Utilisateur non trouvé" });

    req.user = user[0];
    next();
  } catch (err) {
    console.error("Erreur d'authentification:", err);
    res.status(401).json({ success: false, message: "Token invalide ou expiré" });
  }
};

// Gestion des sockets
const onlineUsers = new Map();

io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error("Authentification requise"));

    const decoded = jwt.verify(token, JWT_SECRET);
    const [user] = await pool.execute(
      "SELECT id, name, avatar, status FROM users WHERE id = ?", 
      [decoded.userId]
    );
    
    if (!user.length) return next(new Error("Utilisateur non trouvé"));

    socket.user = user[0];
    next();
  } catch (err) {
    console.error("Erreur d'authentification socket:", err);
    next(new Error("Authentification échouée"));
  }
});

// Événements Socket.io
io.on('connection', async (socket) => {
  const userId = socket.user.id;
  
  // Gestion de la connexion
  onlineUsers.set(userId, socket.id);
  await pool.execute("UPDATE users SET status = 'En ligne' WHERE id = ?", [userId]);
  io.emit('user-status-changed', { userId, status: 'En ligne' });

  // Gestion de la déconnexion
  socket.on('disconnect', async () => {
    onlineUsers.delete(userId);
    await pool.execute("UPDATE users SET status = 'Hors ligne' WHERE id = ?", [userId]);
    io.emit('user-status-changed', { userId, status: 'Hors ligne' });
  });

  // Envoi de message
  socket.on('send-message', async ({ conversationId, content }, callback) => {
    try {
      const conn = await pool.getConnection();
      await conn.beginTransaction();

      // Vérification de la conversation
      const [conversation] = await conn.execute(
        `SELECT user1_id, user2_id FROM conversations 
         WHERE id = ? AND (user1_id = ? OR user2_id = ?)`,
        [conversationId, userId, userId]
      );
      
      if (!conversation.length) throw new Error("Conversation non trouvée");

      const { user1_id, user2_id } = conversation[0];
      const otherUserId = user1_id === userId ? user2_id : user1_id;

      // Insertion du message
      const [result] = await conn.execute(
        `INSERT INTO messages (conversation_id, sender_id, content) 
         VALUES (?, ?, ?)`,
        [conversationId, userId, content]
      );

      // Mise à jour de la conversation
      await conn.execute(
        `UPDATE conversations SET last_message_id = ?, updated_at = NOW() 
         WHERE id = ?`,
        [result.insertId, conversationId]
      );

      // Récupération du message complet
      const [message] = await conn.execute(`
        SELECT m.id, m.content, m.created_at, m.sender_id, 
               u.name as sender_name, u.avatar as sender_avatar,
               m.conversation_id as conversationId
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.id = ?
      `, [result.insertId]);

      await conn.commit();

      const messageData = {
        ...message[0],
        is_read: false
      };

      // Diffusion du message
      const recipientSocketId = onlineUsers.get(otherUserId);
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('new-message', messageData);
      }

      // Confirmation à l'expéditeur
      socket.emit('message-sent', {
        ...messageData,
        is_read: !!recipientSocketId
      });

      // Mise à jour des conversations
      updateConversationList(conversationId, userId, otherUserId);

      callback({ success: true, message: messageData });
    } catch (err) {
      console.error("Erreur d'envoi de message:", err);
      callback({ success: false, message: "Erreur lors de l'envoi du message" });
    }
  });

  // Marquer les messages comme lus
  socket.on('mark-as-read', async ({ conversationId }) => {
    try {
      await pool.execute(
        `UPDATE messages SET read_at = NOW() 
         WHERE conversation_id = ? AND sender_id != ? AND read_at IS NULL`,
        [conversationId, userId]
      );

      const [conversation] = await pool.execute(
        "SELECT user1_id, user2_id FROM conversations WHERE id = ?",
        [conversationId]
      );

      if (conversation.length) {
        const { user1_id, user2_id } = conversation[0];
        const otherUserId = user1_id === userId ? user2_id : user1_id;
        updateConversationList(conversationId, userId, otherUserId);
      }
    } catch (err) {
      console.error("Erreur de marquage des messages:", err);
    }
  });

  // Appels vocaux/vidéo
  socket.on('call-user', ({ to, offer, callType }) => {
    const recipientSocketId = onlineUsers.get(to);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('call-made', {
        from: userId,
        offer,
        callType,
        callerName: socket.user.name,
        callerAvatar: socket.user.avatar
      });
    }
  });

  socket.on('answer-call', ({ to, answer }) => {
    const recipientSocketId = onlineUsers.get(to);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('call-answered', {
        from: userId,
        answer
      });
    }
  });

  socket.on('reject-call', ({ to }) => {
    const recipientSocketId = onlineUsers.get(to);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('call-rejected', {
        from: userId
      });
    }
  });

  socket.on('end-call', ({ to }) => {
    const recipientSocketId = onlineUsers.get(to);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('call-ended', {
        from: userId
      });
    }
  });

  socket.on('ice-candidate', ({ to, candidate }) => {
    const recipientSocketId = onlineUsers.get(to);
    if (recipientSocketId) {
      io.to(recipientSocketId).emit('ice-candidate', {
        from: userId,
        candidate
      });
    }
  });
});

// Fonction helper pour mettre à jour les conversations
async function updateConversationList(conversationId, userId, otherUserId) {
  try {
    const [conversation] = await pool.execute(`
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
             (SELECT COUNT(*) FROM messages 
              WHERE conversation_id = c.id AND sender_id != ? AND read_at IS NULL) as unread_count
      FROM conversations c
      JOIN users u1 ON c.user1_id = u1.id
      JOIN users u2 ON c.user2_id = u2.id
      LEFT JOIN messages m ON c.last_message_id = m.id
      WHERE c.id = ?
    `, [userId, userId, userId, userId, userId, conversationId]);

    if (conversation.length) {
      const convData = conversation[0];
      const senderSocketId = onlineUsers.get(userId);
      const recipientSocketId = onlineUsers.get(otherUserId);

      if (senderSocketId) {
        io.to(senderSocketId).emit('conversation-updated', convData);
      }
      
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('conversation-updated', {
          ...convData,
          other_user_id: userId,
          other_user_name: convData.user1_id === userId ? convData.user1_name : convData.user2_name,
          other_user_avatar: convData.user1_id === userId ? convData.user1_avatar : convData.user2_avatar,
          other_user_status: convData.user1_id === userId ? convData.user1_status : convData.user2_status,
          unread_count: 0
        });
      }
    }
  } catch (err) {
    console.error("Erreur de mise à jour de la conversation:", err);
  }
}

// Routes API

// Inscription
app.post("/api/register", uploadAvatar.single("avatar"), async (req, res) => {
  try {
    const { name, email, password } = req.body;
    
    if (!name || !email || !password) {
      if (req.file) fs.unlinkSync(req.file.path);
      return res.status(400).json({ 
        success: false, 
        message: "Tous les champs sont requis" 
      });
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      const [existing] = await conn.execute(
        "SELECT id FROM users WHERE email = ?", 
        [email]
      );
      
      if (existing.length > 0) {
        if (req.file) fs.unlinkSync(req.file.path);
        return res.status(409).json({ 
          success: false, 
          message: "Email déjà utilisé" 
        });
      }

      const hashedPassword = await bcrypt.hash(password, 12);
      const avatar = req.file 
        ? `/uploads/avatars/${req.file.filename}` 
        : "/uploads/avatars/default.jpg";

      const [result] = await conn.execute(
        `INSERT INTO users (name, email, password, avatar, status) 
         VALUES (?, ?, ?, ?, 'Hors ligne')`, 
        [name, email, hashedPassword, avatar]
      );
      
      const newUser = {
        id: result.insertId,
        name,
        email,
        avatar,
        status: 'Hors ligne'
      };

      await conn.commit();
      
      const token = jwt.sign({ userId: newUser.id }, JWT_SECRET, { 
        expiresIn: JWT_EXPIRES_IN 
      });

      io.emit('new-user', newUser);

      res.status(201).json({ 
        success: true, 
        message: "Inscription réussie",
        token,
        user: newUser
      });
    } catch (err) {
      await conn.rollback();
      if (req.file) fs.unlinkSync(req.file.path);
      throw err;
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error("Erreur d'inscription:", err);
    res.status(500).json({ 
      success: false, 
      message: "Erreur lors de l'inscription" 
    });
  }
});

// Connexion
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        success: false, 
        message: "Email et mot de passe requis" 
      });
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      const [rows] = await conn.execute(
        "SELECT * FROM users WHERE email = ?", 
        [email]
      );
      
      if (rows.length === 0) {
        return res.status(401).json({ 
          success: false, 
          message: "Identifiants incorrects" 
        });
      }

      const user = rows[0];
      const validPass = await bcrypt.compare(password, user.password);
      if (!validPass) {
        return res.status(401).json({ 
          success: false, 
          message: "Identifiants incorrects" 
        });
      }

      await conn.execute(
        "UPDATE users SET status = 'En ligne' WHERE id = ?", 
        [user.id]
      );
      
      await conn.commit();

      const token = jwt.sign({ userId: user.id }, JWT_SECRET, { 
        expiresIn: JWT_EXPIRES_IN 
      });

      const userData = {
        id: user.id,
        name: user.name,
        email: user.email,
        avatar: user.avatar,
        status: "En ligne"
      };

      io.emit('user-status-changed', { 
        userId: user.id, 
        status: 'En ligne' 
      });

      res.json({ 
        success: true, 
        token,
        user: userData
      });
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error("Erreur de connexion:", err);
    res.status(500).json({ 
      success: false, 
      message: "Erreur lors de la connexion" 
    });
  }
});

// Vérification d'authentification
app.get("/api/check-auth", authenticate, async (req, res) => {
  res.json({ 
    success: true, 
    user: req.user 
  });
});

// Déconnexion
app.post("/api/logout", authenticate, async (req, res) => {
  try {
    await pool.execute(
      "UPDATE users SET status = 'Hors ligne' WHERE id = ?", 
      [req.user.id]
    );

    io.emit('user-status-changed', { 
      userId: req.user.id, 
      status: 'Hors ligne' 
    });

    res.json({ 
      success: true, 
      message: "Déconnexion réussie" 
    });
  } catch (err) {
    console.error("Erreur de déconnexion:", err);
    res.status(500).json({ 
      success: false, 
      message: "Erreur lors de la déconnexion" 
    });
  }
});

// Liste des utilisateurs
app.get("/api/users", authenticate, async (req, res) => {
  try {
    const [users] = await pool.execute(
      "SELECT id, name, avatar, status, bio, phone, location FROM users WHERE id != ? ORDER BY name ASC", 
      [req.user.id]
    );
    
    res.json({ success: true, users });
  } catch (err) {
    console.error("Erreur de récupération des utilisateurs:", err);
    res.status(500).json({ success: false, message: "Erreur serveur" });
  }
});

// Profil utilisateur
app.get("/api/profile", authenticate, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      "SELECT id, name, email, avatar, status, bio, phone, location FROM users WHERE id = ?", 
      [req.user.id]
    );
    
    if (rows.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: "Utilisateur non trouvé" 
      });
    }

    res.json({ success: true, user: rows[0] });
  } catch (err) {
    console.error("Erreur de récupération du profil:", err);
    res.status(500).json({ success: false, message: "Erreur serveur" });
  }
});

// Mise à jour du profil
app.put("/api/profile", authenticate, uploadAvatar.single("avatar"), async (req, res) => {
  try {
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

      await conn.execute(
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
        location
      };

      await conn.commit();

      io.emit('user-updated', updatedUser);

      res.json({ 
        success: true, 
        user: updatedUser
      });
    } catch (err) {
      await conn.rollback();
      if (req.file) fs.unlinkSync(req.file.path);
      throw err;
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error("Erreur de mise à jour du profil:", err);
    res.status(500).json({ 
      success: false, 
      message: "Erreur lors de la mise à jour du profil" 
    });
  }
});

// Liste des conversations
app.get("/api/conversations", authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    
    const [conversations] = await pool.execute(`
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
    `, [userId, userId, userId, userId, userId, userId, userId]);

    res.json({ success: true, conversations });
  } catch (err) {
    console.error("Erreur de récupération des conversations:", err);
    res.status(500).json({ success: false, message: "Erreur serveur" });
  }
});

// Récupérer ou créer une conversation
app.get("/api/conversations/:otherUserId", authenticate, async (req, res) => {
  try {
    const userId = req.user.id;
    const otherUserId = req.params.otherUserId;

    const [existing] = await pool.execute(`
      SELECT id FROM conversations 
      WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
    `, [userId, otherUserId, otherUserId, userId]);

    if (existing.length > 0) {
      return res.json({ success: true, conversationId: existing[0].id });
    }

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();
      const [result] = await conn.execute(
        "INSERT INTO conversations (user1_id, user2_id) VALUES (?, ?)",
        [userId, otherUserId]
      );
      
      const [newConversation] = await conn.execute(`
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
      `, [userId, userId, userId, userId, result.insertId]);

      await conn.commit();
      
      const conversationData = newConversation[0];
      
      const initiatorSocketId = onlineUsers.get(userId);
      if (initiatorSocketId) {
        io.to(initiatorSocketId).emit('new-conversation', conversationData);
      }
      
      const otherUserSocketId = onlineUsers.get(otherUserId);
      if (otherUserSocketId) {
        io.to(otherUserSocketId).emit('new-conversation', {
          ...conversationData,
          other_user_id: userId,
          other_user_name: req.user.name,
          other_user_avatar: req.user.avatar,
          other_user_status: req.user.status
        });
      }

      res.json({ success: true, conversationId: result.insertId });
    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error("Erreur de création de conversation:", err);
    res.status(500).json({ success: false, message: "Erreur serveur" });
  }
});

// Récupérer les messages d'une conversation
app.get("/api/messages/:conversationId", authenticate, async (req, res) => {
  try {
    const conversationId = req.params.conversationId;
    const userId = req.user.id;

    // Vérifier que l'utilisateur fait partie de la conversation
    const [conversation] = await pool.execute(
      "SELECT id FROM conversations WHERE id = ? AND (user1_id = ? OR user2_id = ?)",
      [conversationId, userId, userId]
    );
    
    if (!conversation.length) {
      return res.status(403).json({ 
        success: false, 
        message: "Accès non autorisé" 
      });
    }

    const [messages] = await pool.execute(`
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
    `, [conversationId]);

    // Parser le contenu JSON pour les fichiers
    const parsedMessages = messages.map(msg => {
      try {
        if (msg.content && msg.content.startsWith('{') && msg.content.endsWith('}')) {
          const fileData = JSON.parse(msg.content);
          return {
            ...msg,
            content: null,
            fileUrl: fileData.fileUrl,
            fileType: fileData.fileType
          };
        }
        return msg;
      } catch (err) {
        return msg;
      }
    });

    // Marquer les messages comme lus
    await pool.execute(
      "UPDATE messages SET read_at = NOW() WHERE conversation_id = ? AND sender_id != ? AND read_at IS NULL",
      [conversationId, userId]
    );

    res.json({ success: true, messages: parsedMessages });
  } catch (err) {
    console.error("Erreur de récupération des messages:", err);
    res.status(500).json({ success: false, message: "Erreur serveur" });
  }
});

// Upload de fichiers pour les messages
app.post("/api/messages/upload", authenticate, uploadMessageFile.single("file"), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ 
      success: false, 
      message: "Aucun fichier fourni" 
    });
  }

  try {
    const { conversationId } = req.body;
    const userId = req.user.id;
    const fileUrl = `/uploads/messages/${req.file.filename}`;
    const fileType = mime.lookup(req.file.originalname);

    const conn = await pool.getConnection();
    try {
      await conn.beginTransaction();

      // Vérifier l'appartenance à la conversation
      const [conversation] = await conn.execute(
        "SELECT user1_id, user2_id FROM conversations WHERE id = ? AND (user1_id = ? OR user2_id = ?)",
        [conversationId, userId, userId]
      );
      
      if (!conversation.length) {
        fs.unlinkSync(req.file.path);
        return res.status(403).json({ 
          success: false, 
          message: "Accès non autorisé" 
        });
      }

      const { user1_id, user2_id } = conversation[0];
      const otherUserId = user1_id === userId ? user2_id : user1_id;

      // Stocker les métadonnées du fichier
      const fileData = JSON.stringify({ fileUrl, fileType });

      // Insérer le message
      const [result] = await conn.execute(
        "INSERT INTO messages (conversation_id, sender_id, content) VALUES (?, ?, ?)",
        [conversationId, userId, fileData]
      );

      // Mettre à jour la conversation
      await conn.execute(
        "UPDATE conversations SET last_message_id = ?, updated_at = NOW() WHERE id = ?",
        [result.insertId, conversationId]
      );

      // Récupérer le message complet
      const [message] = await conn.execute(`
        SELECT m.id, m.content, m.created_at, m.sender_id, 
               u.name as sender_name, u.avatar as sender_avatar,
               m.conversation_id as conversationId
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE m.id = ?
      `, [result.insertId]);

      await conn.commit();

      const messageData = {
        ...message[0],
        content: null,
        fileUrl,
        fileType,
        is_read: false
      };

      // Diffuser le message
      const recipientSocketId = onlineUsers.get(otherUserId);
      if (recipientSocketId) {
        io.to(recipientSocketId).emit('new-message', messageData);
      }

      // Confirmation à l'expéditeur
      const senderSocketId = onlineUsers.get(userId);
      if (senderSocketId) {
        io.to(senderSocketId).emit('message-sent', {
          ...messageData,
          is_read: !!recipientSocketId
        });
      }

      // Mettre à jour les conversations
      updateConversationList(conversationId, userId, otherUserId);

      res.json({ 
        success: true, 
        message: messageData 
      });
    } catch (err) {
      await conn.rollback();
      fs.unlinkSync(req.file.path);
      throw err;
    } finally {
      conn.release();
    }
  } catch (err) {
    console.error("Erreur d'upload de fichier:", err);
    res.status(500).json({ 
      success: false, 
      message: "Erreur lors de l'envoi du fichier" 
    });
  }
});

// Middleware de gestion des erreurs
app.use((err, req, res, next) => {
  console.error("Erreur non gérée:", err);
  res.status(500).json({ 
    success: false, 
    message: "Une erreur interne est survenue" 
  });
});

// Démarrer le serveur
server.listen(PORT, () => {
  console.log(`Serveur démarré sur le port ${PORT}`);
});

// Gestion des signaux
process.on('SIGTERM', () => {
  console.log('Reçu SIGTERM, fermeture du serveur...');
  server.close(() => {
    console.log('Serveur fermé');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('Reçu SIGINT, fermeture du serveur...');
  server.close(() => {
    console.log('Serveur fermé');
    process.exit(0);
  });
});