const express = require('express');
const mysql = require('mysql2');
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session');
const multer = require('multer');
const xlsx = require('xlsx');
const fs = require('fs');
require('dotenv').config();

const app = express();

// --- CONFIGURACIÓN DE MIDDLEWARE ---
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Configuración de Sesión
app.use(session({
    secret: process.env.SESSION_SECRET || 'secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // true solo si usas HTTPS
        maxAge: 1000 * 60 * 60 * 24 // 24 horas
    }
}));

// Configuración de Multer (Carga de archivos)
const upload = multer({ dest: 'uploads/' });

// --- CONEXIÓN A BASE DE DATOS ---
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASS,
    database: process.env.DB_NAME
});

db.connect(err => {
    if (err) {
        console.error('Error conectando a MySQL:', err);
        return;
    }
    console.log('Conectado a la base de datos MySQL');
});

// --- MIDDLEWARES DE SEGURIDAD (RBAC) ---

// Verificar si está logueado
function requireLogin(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({ error: 'No autenticado' });
    }
    next();
}

// Verificar rol específico
function requireRole(roles) {
    return (req, res, next) => {
        if (!req.session.user || !roles.includes(req.session.user.rol)) {
            return res.status(403).json({ error: 'No autorizado' });
        }
        next();
    };
}

// ==========================================
// RUTAS DE AUTENTICACIÓN
// ==========================================

app.post('/api/auth/register', async (req, res) => {
    const { nombre, correo, password, rol } = req.body;
    
    if (!nombre || !correo || !password) return res.status(400).json({ error: 'Faltan datos' });

    try {
        const hash = await bcrypt.hash(password, 10);
        const rolFinal = rol || 'ASISTENTE';
        
        db.query('INSERT INTO usuarios (nombre, correo, password_hash, rol) VALUES (?,?,?,?)', 
        [nombre, correo, hash, rolFinal], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.status(201).json({ mensaje: 'Usuario registrado' });
        });
    } catch (e) { res.status(500).json({ error: 'Error servidor' }); }
});

app.post('/api/auth/login', (req, res) => {
    const { correo, password } = req.body;
    
    db.query('SELECT * FROM usuarios WHERE correo = ?', [correo], async (err, results) => {
        if (err || results.length === 0) return res.status(401).json({ error: 'Credenciales inválidas' });

        const user = results[0];
        const valid = await bcrypt.compare(password, user.password_hash);

        if (!valid) return res.status(401).json({ error: 'Credenciales inválidas' });

        req.session.user = { id: user.id, nombre: user.nombre, rol: user.rol };
        res.json({ mensaje: 'Login exitoso', usuario: req.session.user });
    });
});

app.post('/api/auth/logout', (req, res) => {
    req.session.destroy(() => {
        res.clearCookie('connect.sid');
        res.json({ mensaje: 'Logout exitoso' });
    });
});

// ==========================================
// RUTAS CRUD INSTRUMENTOS
// ==========================================

app.get('/api/instrumentos', requireLogin, (req, res) => {
    db.query('SELECT * FROM instrumentos', (err, results) => {
        if (err) return res.status(500).json({ error: 'Error BD' });
        res.json(results);
    });
});

app.get('/api/instrumentos/buscar', requireLogin, (req, res) => {
    const q = req.query.q;
    if (!q) return res.json([]);
    
    const query = 'SELECT * FROM instrumentos WHERE nombre LIKE ? OR categoria LIKE ?';
    db.query(query, [`%${q}%`, `%${q}%`], (err, results) => {
        if (err) return res.status(500).json({ error: 'Error BD' });
        res.json(results);
    });
});

app.post('/api/instrumentos', requireLogin, requireRole(['ADMIN', 'ASISTENTE']), (req, res) => {
    const { nombre, categoria, estado, ubicacion } = req.body;
    const query = 'INSERT INTO instrumentos (nombre, categoria, estado, ubicacion) VALUES (?,?,?,?)';
    
    db.query(query, [nombre, categoria, estado || 'DISPONIBLE', ubicacion], (err, result) => {
        if (err) return res.status(500).json({ error: 'Error BD' });
        res.json({ mensaje: 'Creado', id: result.insertId });
    });
});

app.put('/api/instrumentos/:id', requireLogin, requireRole(['ADMIN', 'ASISTENTE']), (req, res) => {
    const { nombre, categoria, estado, ubicacion } = req.body;
    const query = 'UPDATE instrumentos SET nombre=?, categoria=?, estado=?, ubicacion=? WHERE id=?';
    
    db.query(query, [nombre, categoria, estado, ubicacion, req.params.id], (err) => {
        if (err) return res.status(500).json({ error: 'Error BD' });
        res.json({ mensaje: 'Actualizado' });
    });
});

app.delete('/api/instrumentos/:id', requireLogin, requireRole(['ADMIN']), (req, res) => {
    db.query('DELETE FROM instrumentos WHERE id=?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: 'Error BD' });
        res.json({ mensaje: 'Eliminado' });
    });
});

// ==========================================
// RUTAS GESTIÓN DE USUARIOS
// ==========================================

// VER USUARIOS
app.get('/api/usuarios', requireLogin, requireRole(['ADMIN']), (req, res) => {
    const query = 'SELECT id, nombre, correo, rol FROM usuarios';
    db.query(query, (err, results) => {
        if (err) return res.status(500).json({ error: 'Error al obtener usuarios' });
        res.json(results);
    });
});

// ELIMINAR USUARIO
app.delete('/api/usuarios/:id', requireLogin, requireRole(['ADMIN']), (req, res) => {
    // Protección básica: No dejar que el admin se borre a sí mismo
    if (req.session.user.id == req.params.id) {
        return res.status(400).json({ error: 'No puedes eliminar tu propia cuenta actual.' });
    }

    db.query('DELETE FROM usuarios WHERE id=?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: 'Error BD' });
        res.json({ mensaje: 'Usuario eliminado' });
    });
});

// EDITAR USUARIO
app.put('/api/usuarios/:id', requireLogin, requireRole(['ADMIN']), async (req, res) => {
    const { nombre, correo, rol, password } = req.body;
    
    try {
        if (password) {
            // Si hay contraseña nueva, hasheamos y actualizamos todo
            const hash = await bcrypt.hash(password, 10);
            db.query('UPDATE usuarios SET nombre=?, correo=?, rol=?, password_hash=? WHERE id=?', 
                [nombre, correo, rol, hash, req.params.id], (err) => {
                    if (err) return res.status(500).json({ error: 'Error BD' });
                    res.json({ mensaje: 'Usuario actualizado con contraseña' });
                });
        } else {
            // Si NO hay contraseña, actualizamos solo datos
            db.query('UPDATE usuarios SET nombre=?, correo=?, rol=? WHERE id=?', 
                [nombre, correo, rol, req.params.id], (err) => {
                    if (err) return res.status(500).json({ error: 'Error BD' });
                    res.json({ mensaje: 'Usuario actualizado' });
                });
        }
    } catch (e) { res.status(500).json({ error: 'Error servidor' }); }
});

app.delete('/api/usuarios/:id', requireLogin, requireRole(['ADMIN']), (req, res) => {
    if (req.session.user.id == req.params.id) return res.status(400).json({ error: 'No puedes borrarte a ti mismo' });
    db.query('DELETE FROM usuarios WHERE id=?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: 'Error BD' });
        res.json({ mensaje: 'Eliminado' });
    });
});
// ==========================================
// RUTAS EXCEL
// ==========================================

app.post('/api/instrumentos/upload', requireLogin, requireRole(['ADMIN']), upload.single('fileExcel'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Sin archivo' });

    try {
        const wb = xlsx.readFile(req.file.path);
        const data = xlsx.utils.sheet_to_json(wb.Sheets[wb.SheetNames[0]]);
        
        if (data.length === 0) return res.status(400).json({ error: 'Excel vacío' });

        const values = data.map(d => [d.nombre, d.categoria, d.estado || 'DISPONIBLE', d.ubicacion]);
        const query = 'INSERT INTO instrumentos (nombre, categoria, estado, ubicacion) VALUES ?';

        db.query(query, [values], (err) => {
            fs.unlinkSync(req.file.path); 
            if (err) return res.status(500).json({ error: 'Error importando datos' });
            res.json({ mensaje: 'Importación exitosa' });
        });
    } catch (e) {
        res.status(500).json({ error: 'Error procesando Excel' });
    }
});

app.get('/api/instrumentos/download', requireLogin, (req, res) => {
    db.query('SELECT nombre, categoria, estado, ubicacion FROM instrumentos', (err, results) => {
        if (err) return res.status(500).json({ error: 'Error BD' });

        const ws = xlsx.utils.json_to_sheet(results);
        const wb = xlsx.utils.book_new();
        xlsx.utils.book_append_sheet(wb, ws, 'Instrumentos');

        const filename = `Reporte_${Date.now()}.xlsx`;
        const filepath = path.join(__dirname, 'uploads', filename);
        
        xlsx.writeFile(wb, filepath);
        res.download(filepath, filename);
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor en http://localhost:${PORT}`));