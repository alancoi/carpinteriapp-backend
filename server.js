const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());

// Ruta para /app
app.get('/app', (req, res) => {
  const filePath = path.join(__dirname, 'public', 'carpinteriapp_cliente_licencias.html');
  res.sendFile(filePath);
});

// Ruta para /admin
app.get('/admin', (req, res) => {
  const filePath = path.join(__dirname, 'public', 'admin_dashboard.html');
  res.sendFile(filePath);
});

// Ruta raíz
app.get('/', (req, res) => {
  res.json({ mensaje: 'CarpinteriAPP Online' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor en puerto ${PORT}`);
});
