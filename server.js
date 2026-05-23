const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const axios = require('axios');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Conexión a MongoDB
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

// Esquemas MongoDB
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  nombre: String,
  plan: { type: String, enum: ['free', 'premium'], default: 'free' },
  pagado: { type: Boolean, default: false },
  fechaPago: Date,
  usosHoy: { type: Number, default: 0 },
  ultimoResetUsos: { type: Date, default: Date.now },
  createdAt: { type: Date, default: Date.now },
});

const usageSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  tipo: String,
  fecha: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
const Usage = mongoose.model('Usage', usageSchema);

// Middleware de autenticación
const auth = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido' });
  }
};

// AUTENTICACIÓN

// Registro
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, nombre } = req.body;
    
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ error: 'Usuario ya existe' });
    
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    user = new User({
      email,
      password: hashedPassword,
      nombre,
      plan: 'free'
    });
    
    await user.save();
    
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        nombre: user.nombre,
        plan: user.plan,
        usosHoy: user.usosHoy,
        pagado: user.pagado
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: 'Usuario no encontrado' });
    
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ error: 'Contraseña incorrecta' });
    
    const hoy = new Date();
    const ultimoReset = new Date(user.ultimoResetUsos);
    if (hoy.getDate() !== ultimoReset.getDate()) {
      user.usosHoy = 0;
      user.ultimoResetUsos = hoy;
      await user.save();
    }
    
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '7d' });
    
    res.json({
      token,
      user: {
        id: user._id,
        email: user.email,
        nombre: user.nombre,
        plan: user.plan,
        usosHoy: user.usosHoy,
        pagado: user.pagado
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Obtener usuario actual
app.get('/api/auth/me', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    
    const hoy = new Date();
    const ultimoReset = new Date(user.ultimoResetUsos);
    if (hoy.getDate() !== ultimoReset.getDate()) {
      user.usosHoy = 0;
      user.ultimoResetUsos = hoy;
      await user.save();
    }
    
    res.json({
      id: user._id,
      email: user.email,
      nombre: user.nombre,
      plan: user.plan,
      usosHoy: user.usosHoy,
      pagado: user.pagado
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// LÍMITE DE USOS

app.get('/api/usage/check', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    
    const hoy = new Date();
    const ultimoReset = new Date(user.ultimoResetUsos);
    if (hoy.getDate() !== ultimoReset.getDate()) {
      user.usosHoy = 0;
      user.ultimoResetUsos = hoy;
      await user.save();
    }
    
    if (user.plan === 'premium') {
      return res.json({ 
        puedeUsar: true,
        usosRestantes: '∞',
        plan: 'premium'
      });
    }
    
    const puedeUsar = user.usosHoy < 30;
    const usosRestantes = 30 - user.usosHoy;
    
    res.json({
      puedeUsar,
      usosRestantes,
      usosHoy: user.usosHoy,
      plan: 'free'
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/usage/increment', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    
    const hoy = new Date();
    const ultimoReset = new Date(user.ultimoResetUsos);
    if (hoy.getDate() !== ultimoReset.getDate()) {
      user.usosHoy = 0;
      user.ultimoResetUsos = hoy;
      await user.save();
    }
    
    if (user.plan === 'premium') {
      return res.json({ success: true, plan: 'premium' });
    }
    
    if (user.usosHoy >= 30) {
      return res.status(400).json({ error: 'Límite de usos alcanzado' });
    }
    
    user.usosHoy += 1;
    await user.save();
    
    const usage = new Usage({
      userId: user._id,
      tipo: req.body.tipo || 'general'
    });
    await usage.save();
    
    res.json({ 
      success: true,
      usosHoy: user.usosHoy,
      usosRestantes: 30 - user.usosHoy
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PAGOS (MERCADO PAGO)

app.post('/api/payment/create-order', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    const { plan } = req.body;
    
    let precio = 0;
    let titulo = '';
    
    if (plan === 'premium') {
      precio = 9000;
      titulo = 'CarpiteriAPP Premium - $9.000/mes';
    } else {
      precio = 29990;
      titulo = 'CarpiteriAPP - Acceso de por Vida';
    }
    
    const preference = {
      items: [
        {
          title: titulo,
          quantity: 1,
          currency_id: 'ARS',
          unit_price: precio
        }
      ],
      payer: {
        email: user.email,
        name: user.nombre
      },
      back_urls: {
        success: `${process.env.FRONTEND_URL}/payment/success`,
        failure: `${process.env.FRONTEND_URL}/payment/failure`,
        pending: `${process.env.FRONTEND_URL}/payment/pending`
      },
      auto_return: 'approved',
      external_reference: `${user._id}-${plan}`
    };
    
    const response = await axios.post(
      'https://api.mercadopago.com/checkout/preferences',
      preference,
      {
        headers: {
          Authorization: `Bearer ${process.env.MERCADOPAGO_TOKEN}`
        }
      }
    );
    
    res.json({
      id: response.data.id,
      init_point: response.data.init_point
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/payment/webhook', async (req, res) => {
  try {
    const { data } = req.query;
    
    if (!data || !data.id) return res.json({ status: 'received' });
    
    const paymentData = await axios.get(
      `https://api.mercadopago.com/v1/payments/${data.id}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.MERCADOPAGO_TOKEN}`
        }
      }
    );
    
    if (paymentData.data.status === 'approved') {
      const [userId, plan] = paymentData.data.external_reference.split('-');
      
      const user = await User.findById(userId);
      user.plan = plan;
      user.pagado = true;
      user.fechaPago = new Date();
      await user.save();
    }
    
    res.json({ status: 'received' });
  } catch (error) {
    res.json({ status: 'error', error: error.message });
  }
});

// RUTAS DE LA APP

app.post('/api/claude/analyze-photo', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    
    const hoy = new Date();
    const ultimoReset = new Date(user.ultimoResetUsos);
    if (hoy.getDate() !== ultimoReset.getDate()) {
      user.usosHoy = 0;
      user.ultimoResetUsos = hoy;
      await user.save();
    }
    
    if (user.plan === 'free' && user.usosHoy >= 30) {
      return res.status(400).json({ error: 'Límite de usos diario alcanzado. Actualiza a Premium.' });
    }
    
    if (user.plan === 'free') {
      user.usosHoy += 1;
      await user.save();
    }
    
    const { imageData } = req.body;
    const apiKey = process.env.ANTHROPIC_API_KEY;
    
    const response = await axios.post(
      'https://api.anthropic.com/v1/messages',
      {
        model: 'claude-opus-4-1-20250805',
        max_tokens: 2000,
        messages: [
          {
            role: 'user',
            content: [
              {
                type: 'image',
                source: {
                  type: 'base64',
                  media_type: 'image/jpeg',
                  data: imageData.split(',')[1]
                }
              },
              {
                type: 'text',
                text: `Eres experto carpintero. Analiza esta foto profesionalmente:
1. Mueble: Tipo y descripción
2. Dimensiones: Alto × Ancho × Profundo (cm)
3. Materiales: Recomendados con precios
4. Costo estimado: Total de materiales
5. Pasos construcción: 4-5 pasos claros
6. Dificultad: Principiante/Intermedio/Avanzado
7. Tiempo: Horas de construcción
8. Precio venta sugerido: Mercado competitivo
Sé muy específico y profesional.`
              }
            ]
          }
        ]
      },
      {
        headers: {
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01'
        }
      }
    );
    
    res.json({
      analysis: response.data.content[0].text,
      usosRestantes: user.plan === 'premium' ? '∞' : (30 - user.usosHoy)
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/claude/chat', auth, async (req, res) => {
  try {
    const user = await User.findById(req.userId);
    
    const hoy = new Date();
    const ultimoReset = new Date(user.ultimoResetUsos);
    if (hoy.getDate() !== ultimoReset.getDate()) {
      user.usosHoy = 0;
      user.ultimoResetUsos = hoy;
      await user.save();
    }
    
    if (user.plan === 'free' && user.usosHoy >= 30) {
      return res.status(400).json({ error: 'Límite de usos diario alcanzado. Actualiza a Premium.' });
    }
    
    if (user.plan === 'free') {
      user.usosHoy += 1;
      await user.save();
    }
    
    const { message } = req.body;
    const apiKey = process.env.ANTHROPIC_API_KEY;
    
    const response = await axios.post(
      'https://api.anthropic.com/v1/messages',
      {
        model: 'claude-opus-4-1-20250805',
        max_tokens: 2000,
        messages: [
          {
            role: 'user',
            content: `Eres experto carpintero con 20+ años. Hablas español fluidamente.
Pregunta: "${message}"
Responde de forma profesional, directo y útil. Números específicos cuando sea posible.`
          }
        ]
      },
      {
        headers: {
          'x-api-key': apiKey,
          'anthropic-version': '2023-06-01'
        }
      }
    );
    
    res.json({
      response: response.data.content[0].text,
      usosRestantes: user.plan === 'premium' ? '∞' : (30 - user.usosHoy)
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// SERVIDOR

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Servidor ejecutándose en puerto ${PORT}`);
});

module.exports = app;
