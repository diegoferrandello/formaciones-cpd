require('dotenv').config();
const express = require('express');
const { Sequelize, DataTypes, Op } = require('sequelize');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use(express.static('public'));

// Uploads directory
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir, { recursive: true });
app.use('/uploads', express.static(uploadsDir));

// Multer config for photo uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadsDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `foto_${Date.now()}_${Math.random().toString(36).slice(2, 8)}${ext}`);
  }
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

// ─── DATABASE ───
const DATABASE_URL = process.env.DATABASE_URL || 'postgres://localhost:5432/formaciones_cpd';
const sequelize = new Sequelize(DATABASE_URL, {
  dialect: 'postgres',
  logging: false,
  dialectOptions: DATABASE_URL.includes('railway') ? {
    ssl: { require: true, rejectUnauthorized: false }
  } : {}
});

// ─── MODELS ───
const User = sequelize.define('User', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  nombre: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  password: { type: DataTypes.STRING, allowNull: false },
  rol: { type: DataTypes.ENUM('admin', 'formador'), defaultValue: 'formador' },
  activo: { type: DataTypes.BOOLEAN, defaultValue: true }
}, { tableName: 'users', timestamps: true });

const Formacion = sequelize.define('Formacion', {
  id: { type: DataTypes.INTEGER, primaryKey: true, autoIncrement: true },
  titulo: { type: DataTypes.STRING, allowNull: false },
  descripcion: { type: DataTypes.TEXT },
  tipo: { type: DataTypes.ENUM('producto', 'tecnica_venta', 'lanzamiento', 'otro'), defaultValue: 'producto' },
  fecha: { type: DataTypes.DATEONLY, allowNull: false },
  hora_inicio: { type: DataTypes.TIME },
  hora_fin: { type: DataTypes.TIME },
  cadena: { type: DataTypes.STRING },
  pdv_nombre: { type: DataTypes.STRING },
  pdv_direccion: { type: DataTypes.STRING },
  ciudad: { type: DataTypes.STRING },
  estado: { type: DataTypes.ENUM('planificada', 'confirmada', 'realizada', 'cancelada'), defaultValue: 'planificada' },
  asistentes_esperados: { type: DataTypes.INTEGER },
  asistentes_reales: { type: DataTypes.INTEGER },
  notas: { type: DataTypes.TEXT },
  fotos: { type: DataTypes.JSON, defaultValue: [] },
  formador_id: { type: DataTypes.INTEGER, allowNull: false },
  creado_por: { type: DataTypes.INTEGER }
}, { tableName: 'formaciones', timestamps: true });

// Relations
User.hasMany(Formacion, { foreignKey: 'formador_id', as: 'formaciones' });
Formacion.belongsTo(User, { foreignKey: 'formador_id', as: 'formador' });

// ─── AUTH MIDDLEWARE ───
const JWT_SECRET = process.env.JWT_SECRET || 'formaciones_cpd_secret_2026';

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token requerido' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (e) {
    res.status(401).json({ error: 'Token inválido' });
  }
}

function adminOnly(req, res, next) {
  if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Solo administradores' });
  next();
}

// ─── AUTH ROUTES ───
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ where: { email, activo: true } });
    if (!user || !bcrypt.compareSync(password, user.password)) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }
    const token = jwt.sign({ id: user.id, nombre: user.nombre, email: user.email, rol: user.rol }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, nombre: user.nombre, email: user.email, rol: user.rol } });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  const user = await User.findByPk(req.user.id, { attributes: ['id', 'nombre', 'email', 'rol'] });
  res.json(user);
});

// ─── USERS ROUTES (admin only) ───
app.get('/api/users', authMiddleware, async (req, res) => {
  const users = await User.findAll({ attributes: ['id', 'nombre', 'email', 'rol', 'activo'], order: [['nombre', 'ASC']] });
  res.json(users);
});

app.post('/api/users', authMiddleware, adminOnly, async (req, res) => {
  try {
    const { nombre, email, password, rol } = req.body;
    const hash = bcrypt.hashSync(password, 10);
    const user = await User.create({ nombre, email, password: hash, rol: rol || 'formador' });
    res.json({ id: user.id, nombre: user.nombre, email: user.email, rol: user.rol });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.put('/api/users/:id', authMiddleware, adminOnly, async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id);
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    const { nombre, email, rol, activo, password } = req.body;
    if (nombre) user.nombre = nombre;
    if (email) user.email = email;
    if (rol) user.rol = rol;
    if (activo !== undefined) user.activo = activo;
    if (password) user.password = bcrypt.hashSync(password, 10);
    await user.save();
    res.json({ id: user.id, nombre: user.nombre, email: user.email, rol: user.rol, activo: user.activo });
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

// ─── FORMACIONES ROUTES ───
app.get('/api/formaciones', authMiddleware, async (req, res) => {
  try {
    const { mes, anio, formador_id, estado, desde, hasta } = req.query;
    const where = {};
    
    if (mes && anio) {
      const start = new Date(anio, mes - 1, 1);
      const end = new Date(anio, mes, 0);
      where.fecha = { [Op.between]: [start.toISOString().split('T')[0], end.toISOString().split('T')[0]] };
    } else if (desde && hasta) {
      where.fecha = { [Op.between]: [desde, hasta] };
    }
    
    if (formador_id) where.formador_id = formador_id;
    if (estado) where.estado = estado;

    const formaciones = await Formacion.findAll({
      where,
      include: [{ model: User, as: 'formador', attributes: ['id', 'nombre', 'email'] }],
      order: [['fecha', 'ASC'], ['hora_inicio', 'ASC']]
    });
    res.json(formaciones);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/formaciones/:id', authMiddleware, async (req, res) => {
  const f = await Formacion.findByPk(req.params.id, {
    include: [{ model: User, as: 'formador', attributes: ['id', 'nombre', 'email'] }]
  });
  if (!f) return res.status(404).json({ error: 'No encontrada' });
  res.json(f);
});

app.post('/api/formaciones', authMiddleware, async (req, res) => {
  try {
    const data = { ...req.body, creado_por: req.user.id };
    if (req.user.rol === 'formador') data.formador_id = req.user.id;
    const f = await Formacion.create(data);
    const full = await Formacion.findByPk(f.id, {
      include: [{ model: User, as: 'formador', attributes: ['id', 'nombre', 'email'] }]
    });
    res.json(full);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.put('/api/formaciones/:id', authMiddleware, async (req, res) => {
  try {
    const f = await Formacion.findByPk(req.params.id);
    if (!f) return res.status(404).json({ error: 'No encontrada' });
    if (req.user.rol === 'formador' && f.formador_id !== req.user.id) {
      return res.status(403).json({ error: 'Solo podés editar tus formaciones' });
    }
    await f.update(req.body);
    const full = await Formacion.findByPk(f.id, {
      include: [{ model: User, as: 'formador', attributes: ['id', 'nombre', 'email'] }]
    });
    res.json(full);
  } catch (e) {
    res.status(400).json({ error: e.message });
  }
});

app.delete('/api/formaciones/:id', authMiddleware, async (req, res) => {
  const f = await Formacion.findByPk(req.params.id);
  if (!f) return res.status(404).json({ error: 'No encontrada' });
  if (req.user.rol === 'formador' && f.formador_id !== req.user.id) {
    return res.status(403).json({ error: 'Solo podés eliminar tus formaciones' });
  }
  await f.destroy();
  res.json({ ok: true });
});

// ─── PHOTO UPLOAD ───
app.post('/api/formaciones/:id/fotos', authMiddleware, upload.array('fotos', 10), async (req, res) => {
  try {
    const f = await Formacion.findByPk(req.params.id);
    if (!f) return res.status(404).json({ error: 'No encontrada' });
    const nuevasFotos = req.files.map(file => `/uploads/${file.filename}`);
    const fotosActuales = f.fotos || [];
    await f.update({ fotos: [...fotosActuales, ...nuevasFotos] });
    res.json({ fotos: f.fotos });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── STATS ───
app.get('/api/stats', authMiddleware, async (req, res) => {
  try {
    const { mes, anio } = req.query;
    const where = {};
    if (mes && anio) {
      const start = new Date(anio, mes - 1, 1);
      const end = new Date(anio, mes, 0);
      where.fecha = { [Op.between]: [start.toISOString().split('T')[0], end.toISOString().split('T')[0]] };
    }

    const total = await Formacion.count({ where });
    const realizadas = await Formacion.count({ where: { ...where, estado: 'realizada' } });
    const planificadas = await Formacion.count({ where: { ...where, estado: 'planificada' } });
    const confirmadas = await Formacion.count({ where: { ...where, estado: 'confirmada' } });
    const canceladas = await Formacion.count({ where: { ...where, estado: 'cancelada' } });
    
    const porFormador = await Formacion.findAll({
      where,
      attributes: ['formador_id', [sequelize.fn('COUNT', sequelize.col('Formacion.id')), 'total']],
      include: [{ model: User, as: 'formador', attributes: ['nombre'] }],
      group: ['formador_id', 'formador.id', 'formador.nombre']
    });

    const porTipo = await Formacion.findAll({
      where,
      attributes: ['tipo', [sequelize.fn('COUNT', sequelize.col('id')), 'total']],
      group: ['tipo']
    });

    res.json({ total, realizadas, planificadas, confirmadas, canceladas, porFormador, porTipo });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ─── SERVE FRONTEND ───
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── INIT ───
async function init() {
  try {
    await sequelize.authenticate();
    console.log('✅ PostgreSQL conectado');
    await sequelize.sync({ alter: true });
    console.log('✅ Modelos sincronizados');

    const adminCount = await User.count({ where: { rol: 'admin' } });
    if (adminCount === 0) {
      await User.create({
        nombre: 'Diego Ferrandello',
        email: 'admin@nexxbio.com',
        password: bcrypt.hashSync('admin2026', 10),
        rol: 'admin'
      });
      console.log('✅ Admin creado: admin@nexxbio.com / admin2026');
    }

    const PORT = process.env.PORT || 3000;
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`🚀 Formaciones CPD corriendo en puerto ${PORT}`);
    });
  } catch (e) {
    console.error('❌ Error de inicio:', e.message);
    process.exit(1);
  }
}

init();
