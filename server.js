const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());

// Middleware para servir archivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// Ruta para /app
app.get('/app', (req, res) => {
  try {
    const filePath = path.join(__dirname, 'public', 'carpinteriapp_cliente_licencias.html');
    const html = fs.readFileSync(filePath, 'utf8');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (error) {
    res.status(500).send('Error: ' + error.message);
  }
});

// Ruta para /admin
app.get('/admin', (req, res) => {
  try {
    const filePath = path.join(__dirname, 'public', 'admin_dashboard.html');
    const html = fs.readFileSync(filePath, 'utf8');
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  } catch (error) {
    res.status(500).send('Error: ' + error.message);
  }
});

// Ruta raíz
app.get('/', (req, res) => {
  res.json({ mensaje: 'CarpinteriAPP Online' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor en puerto ${PORT}`);
});
