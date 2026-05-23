const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const axios = require('axios');
const nodemailer = require('nodemailer');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

// Conectar MongoDB
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/carpiteriapp', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// ==================== SCHEMAS ====================

// Usuario (Cliente)
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  nombre: String,
  licenseId: { type: mongoose.Schema.Types.ObjectId, ref: 'License' },
  usosHoy: { type: Number, default: 0 },
  ultimoResetUsos: { type: Date, default: Date.now },
  ultimaIP: String,
  ultimoDispositivo: String,
  activo: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Licencia (Cliente que pagó)
const licenseSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  shopifyOrderId: String,
  nombre: String,
  estado: { type: String, enum: ['activa', 'suspendida', 'expirada'], default: 'activa' },
  usosLimiteDiario: { type: Number, default: 20 },
  plan: { type: String, enum: ['pago-unico', 'premium'], default: 'pago-unico' },
  fechaCompra: { type: Date, default: Date.now },
  fechaVencimiento: { type: Date, default: () => new Date(Date.now() + 365 * 24 * 60 * 60 * 1000) },
  totalUsosHistorico: { type: Number, default: 0 },
  usosEsteMes: { type: Number, default: 0 },
  diasActivo: { type: Number, default: 0 },
  ipsUsadas: [{ ip: String, fecha: Date, dispositivo: String }],
  ultimoAcceso: Date,
  alertas: [{ tipo: String, mensaje: String, fecha: Date }],
  premium: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const License = mongoose.model('License', licenseSchema);

// Analytics (Tracking de uso)
const analyticsSchema = new mongoose.Schema({
  licenseId: { type: mongoose.Schema.Types.ObjectId, ref: 'License' },
  email: String,
  pregunta: String,
  respuesta: String,
  tokensUsados: Number,
  ip: String,
  dispositivo: String,
  horario: { type: Date, default: Date.now },
  duracionMs: Number
});

const Analytics = mongoose.model('Analytics', analyticsSchema);

// Admin (Tu usuario)
const adminSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: String,
  nombre: String,
  rol: { type: String, default: 'admin' },
  createdAt: { type: Date, default: Date.now }
});

const Admin = mongoose.model('Admin', adminSchema);

// ==================== MIDDLEWARE ====================

const auth = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    req.userId = decoded.id;
    req.userEmail = decoded.email;
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido' });
  }
};

const adminAuth = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret123');
    if (decoded.rol !== 'admin') return res.status(403).json({ error: 'No autorizado' });
    
    req.adminId = decoded.id;
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido' });
  }
};

// ==================== FUNCIONES ÚTILES ====================

const obtenerIP = (req) => {
  return req.headers['x-forwarded-for']?.split(',')[0].trim() || 
         req.connection.remoteAddress || 
         req.socket.remoteAddress;
};

const obtenerDispositivo = (userAgent) => {
  if (!userAgent) return 'Desconocido';
  if (/mobile|android/i.test(userAgent)) return 'Mobile';
  if (/tablet|ipad/i.test(userAgent)) return 'Tablet';
  return 'Desktop';
};

const generarContraseña = () => {
  return Math.random().toString(36).substring(2, 10) + 
         Math.random().toString(36).substring(2, 10);
};

const enviarEmailBienvenida = async (email, nombre, contraseña) => {
  try {
    // Aquí va tu config de nodemailer
    // Por ahora solo logging
    console.log(`📧 Email enviado a ${email}`);
    console.log(`Usuario: ${email}`);
    console.log(`Contraseña: ${contraseña}`);
  } catch (error) {
    console.error('Error enviando email:', error);
  }
};

// ==================== RUTAS CLIENTE ====================

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const ip = obtenerIP(req);
    const dispositivo = obtenerDispositivo(req.headers['user-agent']);

    // Verificar que existe licencia
    const license = await License.findOne({ email });
    if (!license) return res.status(400).json({ error: 'No tienes acceso' });
    if (license.estado !== 'activa') return res.status(400).json({ error: 'Licencia suspendida' });

    // Verificar que solo usa 1 dispositivo
    const ultimaIP = license.ipsUsadas[0]?.ip;
    if (ultimaIP && ultimaIP !== ip) {
      license.alertas.push({
        tipo: 'intento-acceso-otra-ip',
        mensaje: `Intento de acceso desde IP: ${ip}`,
        fecha: new Date()
      });
      await license.save();
      return res.status(400).json({ error: 'Este usuario solo puede usarse desde un dispositivo' });
    }

    // Buscar o crear usuario
    let user = await User.findOne({ email });
    if (!user) {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      user = new User({
        email,
        password: hashedPassword,
        nombre: license.nombre,
        licenseId: license._id,
        ultimaIP: ip,
        ultimoDispositivo: dispositivo
      });
      await user.save();
    }

    // Validar contraseña
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Contraseña incorrecta' });

    // Reset usos diarios
    const hoy = new Date();
    const ultimoReset = new Date(user.ultimoResetUsos);
    if (hoy.getDate() !== ultimoReset.getDate()) {
      user.usosHoy = 0;
      user.ultimoResetUsos = hoy;
    }

    // Actualizar license
    license.ultimoAcceso = new Date();
    if (!license.ipsUsadas.some(i => i.ip === ip)) {
      license.ipsUsadas.unshift({ ip, fecha: new Date(), dispositivo });
    }
    license.diasActivo += 1;
    await license.save();
    await user.save();

    const token = jwt.sign({ id: user._id, email }, process.env.JWT_SECRET || 'secret123', { expiresIn: '7d' });

    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        nombre: user.nombre,
        usosHoy: user.usosHoy,
        usosRestantes: license.usosLimiteDiario - user.usosHoy
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Cambiar contraseña
app.post('/api/auth/change-password', auth, async (req, res) => {
  try {
    const { passwordActual, passwordNueva } = req.body;
    const user = await User.findById(req.userId);

    const isMatch = await bcrypt.compare(passwordActual, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Contraseña actual incorrecta' });

    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(passwordNueva, salt);
    await user.save();

    res.json({ mensaje: 'Contraseña cambiada exitosamente' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Verificar uso diario
app.get('/api/usage/check', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const license = await License.findById(user.licenseId);

    const hoy = new Date();
    const ultimoReset = new Date(user.ultimoResetUsos);
    if (hoy.getDate() !== ultimoReset.getDate()) {
      user.usosHoy = 0;
      user.ultimoResetUsos = hoy;
      await user.save();
    }

    const puedeUsar = user.usosHoy < license.usosLimiteDiario;
    const usosRestantes = license.usosLimiteDiario - user.usosHoy;

    res.json({
      puedeUsar,
      usosRestantes,
      usosHoy: user.usosHoy,
      usosLimiteDiario: license.usosLimiteDiario
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Chat con Claude
app.post('/api/claude/chat', auth, async (req, res) => {
  try {
    const { message } = req.body;
    const user = await User.findById(req.userId);
    const license = await License.findById(user.licenseId);

    // Verificar límite
    if (user.usosHoy >= license.usosLimiteDiario) {
      return res.status(400).json({ error: 'Límite de usos alcanzado' });
    }

    // Llamar a Claude
    const startTime = Date.now();
    const response = await axios.post(
      'https://api.anthropic.com/v1/messages',
      {
        model: 'claude-3-5-haiku-20241022',
        max_tokens: 1000,
        messages: [
          {
            role: 'user',
            content: `Eres experto carpintero con 20 años de experiencia. Responde brevemente y práctico: "${message}"`
          }
        ]
      },
      {
        headers: {
          'x-api-key': process.env.ANTHROPIC_API_KEY,
          'anthropic-version': '2023-06-01'
        }
      }
    );

    const duracionMs = Date.now() - startTime;
    const respuesta = response.data.content[0].text;
    const ip = obtenerIP(req);
    const dispositivo = obtenerDispositivo(req.headers['user-agent']);

    // Incrementar usos
    user.usosHoy += 1;
    license.totalUsosHistorico += 1;
    license.usosEsteMes += 1;
    await user.save();
    await license.save();

    // Guardar analytics
    const analytic = new Analytics({
      licenseId: license._id,
      email: user.email,
      pregunta: message,
      respuesta: respuesta.substring(0, 200),
      tokensUsados: response.data.usage.input_tokens + response.data.usage.output_tokens,
      ip,
      dispositivo,
      duracionMs
    });
    await analytic.save();

    res.json({
      response: respuesta,
      usosRestantes: license.usosLimiteDiario - user.usosHoy
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== RUTAS ADMIN ====================

// Login Admin
app.post('/api/admin/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    let admin = await Admin.findOne({ email });
    
    // Crear admin por primera vez
    if (!admin && email === 'carpinteriAPP' && password === 'Alancoi1994.') {
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);
      admin = new Admin({
        email,
        password: hashedPassword,
        nombre: 'Admin CarpiteriAPP',
        rol: 'admin'
      });
      await admin.save();
    } else if (admin) {
      const isMatch = await bcrypt.compare(password, admin.password);
      if (!isMatch) return res.status(400).json({ error: 'Contraseña incorrecta' });
    } else {
      return res.status(400).json({ error: 'Credenciales inválidas' });
    }

    const token = jwt.sign(
      { id: admin._id, email: admin.email, rol: 'admin' },
      process.env.JWT_SECRET || 'secret123',
      { expiresIn: '7d' }
    );

    res.json({ token, admin: { email: admin.email, nombre: admin.nombre } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Dashboard - Estadísticas generales
app.get('/api/admin/dashboard', adminAuth, async (req, res) => {
  try {
    const totalClientes = await License.countDocuments();
    const clientesActivos = await License.countDocuments({ estado: 'activa' });
    const clientesSuspendidos = await License.countDocuments({ estado: 'suspendida' });
    
    const totalUsosHoy = await Analytics.countDocuments({
      horario: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) }
    });

    const licenses = await License.find();
    const usosPromedioDiario = licenses.length > 0 
      ? (licenses.reduce((sum, l) => sum + (l.usosEsteMes / 30), 0) / licenses.length).toFixed(2)
      : 0;

    const ingresosTotales = totalClientes * 29990;
    const tuComision = ingresosTotales * 0.4;

    const alertas = await License.aggregate([
      { $unwind: '$alertas' },
      { $sort: { 'alertas.fecha': -1 } },
      { $limit: 10 }
    ]);

    res.json({
      resumenGeneral: {
        totalClientes,
        clientesActivos,
        clientesSuspendidos,
        ingresosTotales,
        tuComision
      },
      uso: {
        totalUsosHoy,
        usosPromedioDiario,
        usosEstesMes: licenses.reduce((sum, l) => sum + l.usosEsteMes, 0)
      },
      alertas: alertas.slice(0, 10)
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Lista de clientes
app.get('/api/admin/clientes', adminAuth, async (req, res) => {
  try {
    const { page = 1, limite = 20, estado = 'todos' } = req.query;
    const skip = (page - 1) * limite;

    const filtro = estado !== 'todos' ? { estado } : {};
    const clientes = await License.find(filtro)
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(parseInt(limite));

    const total = await License.countDocuments(filtro);

    const clientesFormateados = await Promise.all(clientes.map(async (c) => {
      const user = await User.findOne({ licenseId: c._id });
      const usosEsteMes = c.usosEsteMes;
      const diasActivo = c.diasActivo;
      
      return {
        id: c._id,
        email: c.email,
        nombre: c.nombre,
        estado: c.estado,
        fechaCompra: c.fechaCompra,
        usosEsteMes,
        diasActivo,
        ultimoAcceso: c.ultimoAcceso,
        ipsUsadas: c.ipsUsadas.length,
        tieneAlertas: c.alertas.length > 0,
        premium: c.premium
      };
    }));

    res.json({
      clientes: clientesFormateados,
      total,
      pagina: page,
      totalPaginas: Math.ceil(total / limite)
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Detalle de cliente
app.get('/api/admin/cliente/:id', adminAuth, async (req, res) => {
  try {
    const license = await License.findById(req.params.id);
    if (!license) return res.status(404).json({ error: 'Cliente no encontrado' });

    const analytics = await Analytics.find({ licenseId: license._id })
      .sort({ horario: -1 })
      .limit(50);

    const user = await User.findOne({ licenseId: license._id });

    res.json({
      cliente: license,
      usuario: user ? { email: user.email, createdAt: user.createdAt } : null,
      actividad: analytics,
      alertas: license.alertas
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Suspender cliente
app.post('/api/admin/cliente/:id/suspender', adminAuth, async (req, res) => {
  try {
    const license = await License.findByIdAndUpdate(
      req.params.id,
      { estado: 'suspendida' },
      { new: true }
    );
    res.json({ mensaje: 'Cliente suspendido', license });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Reactivar cliente
app.post('/api/admin/cliente/:id/reactivar', adminAuth, async (req, res) => {
  try {
    const license = await License.findByIdAndUpdate(
      req.params.id,
      { estado: 'activa' },
      { new: true }
    );
    res.json({ mensaje: 'Cliente reactivado', license });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Analytics - Preguntas más frecuentes
app.get('/api/admin/analytics/preguntas-frecuentes', adminAuth, async (req, res) => {
  try {
    const preguntas = await Analytics.aggregate([
      { $group: { _id: '$pregunta', total: { $sum: 1 } } },
      { $sort: { total: -1 } },
      { $limit: 20 }
    ]);

    res.json(preguntas);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Analytics - Horarios de uso
app.get('/api/admin/analytics/horarios', adminAuth, async (req, res) => {
  try {
    const horarios = await Analytics.aggregate([
      {
        $group: {
          _id: { $hour: '$horario' },
          total: { $sum: 1 }
        }
      },
      { $sort: { _id: 1 } }
    ]);

    res.json(horarios);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Webhook Shopify (recibe clientes que compraron)
app.post('/api/shopify/webhook', async (req, res) => {
  try {
    const order = req.body;
    
    const email = order.customer?.email || order.email;
    const nombre = order.customer?.first_name || 'Cliente';
    const orderId = order.id;

    // Verificar si ya existe
    let license = await License.findOne({ shopifyOrderId: orderId });
    if (license) return res.json({ mensaje: 'License ya existe' });

    // Crear licencia
    const contraseña = generarContraseña();
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(contraseña, salt);

    license = new License({
      email,
      shopifyOrderId: orderId,
      nombre,
      estado: 'activa',
      usosLimiteDiario: 20,
      plan: 'pago-unico'
    });
    await license.save();

    // Crear usuario
    const user = new User({
      email,
      password: hashedPassword,
      nombre,
      licenseId: license._id,
      activo: true
    });
    await user.save();

    // Enviar email
    await enviarEmailBienvenida(email, nombre, contraseña);

    res.json({ mensaje: 'Cliente creado exitosamente' });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ==================== INICIO ====================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor en puerto ${PORT}`);
  console.log(`📊 Admin: carpinteriAPP / Alancoi1994.`);
});
