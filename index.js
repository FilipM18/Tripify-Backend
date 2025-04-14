import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import pkg from '@supabase/pg';
const { Pool } = pkg;
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

dotenv.config();
const app = express();
const port = 3000;


const JWT_SECRET = process.env.JWT_SECRET

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN
  
  if (!token) {
    return res.status(401).json({ success: false, error: 'Pristup zamietnuty. Token nebol nenajdeny.' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, error: 'Token je neplatny.' });
    }
    req.user = user;
    next();
  });
};

const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/');
    },
    filename: (req, file, cb) => {
        const uniqueName = `${Date.now()}-${file.originalname}`;
        cb(null, true ? uniqueName : file.originalname);
    },
});
const upload = multer({ storage });

app.post('/auth/register', upload.single('pfp'), async (req, res) => {
    try {
        const { username, email, password, phoneNumber} = req.body;
        console.log(req.body);
        console.log(req.file); // Debug
        if (!username || !email || !password) {
            return res.status(400).json({ success: false, error: 'Username, email, a heslo su povinne.' });
        }
        if (password.length < 8) {
            return res.status(400).json({ success: false, error: 'Heslo musi mat aspon 8 znakov' });
        }
        if (phoneNumber && phoneNumber.length != 10) {
            return res.status(400).json({ success: false, error: 'Tel. cislo musi mat 10 znakov' });
        }

        const sanitizedPhoneNumber = phoneNumber === '' ? null : phoneNumber;
        const photoUrl = req.file ? `/uploads/${req.file.filename}` : null;

        const hashedPassword = await bcrypt.hash(password, 12);

        const query = `
            INSERT INTO users (username, email, password, tel_num, photo_url)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, username, email;
        `;
        const result = await pool.query(query, [username, email, hashedPassword, sanitizedPhoneNumber, photoUrl]);

        const newUser = result.rows[0];
        
        const token = jwt.sign(
            { id: newUser.id, email: newUser.email, username: newUser.username },
            JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({ success: true, user: newUser, token });
    } catch (error) {
        if (error.code === '23505') { 
            return res.status(409).json({ success: false, error: 'Pouzivatel uz existuje' });
        }
        console.error(error);
        res.status(500).json({ success: false, error: 'Registracia zlyhala' });
    }
});

app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, error: 'Email a heslo su povinne.' });
        }
        const userQuery = await pool.query('SELECT id, email, password, username FROM users WHERE email = $1', [email]);
        if (userQuery.rowCount === 0) return res.status(401).json({ success: false, error: 'Invalidne udaje' });

        const user = userQuery.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ success: false, error: 'Invalidne udaje' });

        const token = jwt.sign(
            { id: user.id, email: user.email, username: user.username },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({ 
            success: true, 
            userId: user.id, 
            email: user.email,
            token 
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Prihlasenie zlyhalo' });
    }
});

app.get('/likes/:type/:id', authenticateToken, async (req, res) => {
    try { 
        const { type, id } = req.params;
        if (isNaN(id)) {
            return res.status(400).json({ success: false, error: 'ID musí byť číslo.' });
        }
        let query = '';
        
        if (type === 'trip') {
        query = 'SELECT user_id FROM likes WHERE trip_id = $1';
        } else if (type === 'comment') {
        query = 'SELECT user_id FROM likes WHERE comment_id = $1';
        }
        const result = await pool.query(query, [id]);

        if (result.rows.length === 0 && type === 'trip') {
            return res.status(404).json({ success: false, error: 'Vylet nebol najdeny' });
        }
        if (result.rows.length === 0 && type === 'comment') {
            return res.status(404).json({ success: false, error: 'Komentar nebol najdeny' });
        }
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Neexistujuci typ' });
        }
        const likes = result.rows.map(row => row.user_id);
        console.log(likes);
        res.json({ success: true, likes });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Chyba databazy' });
    }
});

app.get('/comments/:tripId', authenticateToken, async (req, res) => {    
    try {
        console.log(req.params);
        const { tripId } = req.params;
        if (!tripId || isNaN(tripId)) {
            return res.status(400).json({ success: false, error: 'ID výletu musí byť číslo.' });
        }
        const query = `
                SELECT user_id, comment_text, created_at
                FROM comments WHERE trip_id = $1 and parent_comment_id IS NOT NULL;
            `;
        const result = await pool.query(query, [tripId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Vylet nebol najdeny' });
        }

        const comments = result.rows.map(row => ({
            userId: row.user_id,
            commentText: row.comment_text,
            createdAt: row.created_at,
        }));
        console.log(comments);
        res.json({ success: true, comments });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Chyba databazy' });
    }
});

app.get('/trips/:tripId', authenticateToken, async (req, res) => {
    try {
        console.log(req.params); // Debug
        const { tripId } = req.params;
        if (!tripId || isNaN(tripId)) {
            return res.status(400).json({ success: false, error: 'ID výletu musí byť číslo.' });
        }
        const query = `
            SELECT t.id, u.username, t.ended_at, t.distance_km, t.duration_seconds, t.average_pace, t.info,
                ST_AsGeoJSON(t.route_geometry) AS route,
                COALESCE(json_agg(tp.photo_url) FILTER (WHERE tp.photo_url IS NOT NULL), '[]') AS photo_urls,
                (SELECT COUNT(*) FROM likes WHERE trip_id = t.id) AS likes_count,
                (SELECT COUNT(*) FROM comments WHERE trip_id = t.id) AS comments_count,
                COALESCE(json_agg(c.comment_text) FILTER (WHERE c.trip_id = t.id), '[]') AS comments
            FROM trips t 
            JOIN users u ON t.user_id = u.id
            LEFT JOIN trip_photos tp ON t.id = tp.trip_id
            LEFT JOIN comments c ON c.trip_id = t.id
            WHERE t.id = $1
            GROUP BY t.id, u.username, t.ended_at, t.distance_km, t.duration_seconds, t.average_pace, t.info, t.route_geometry;
        `;

        const result = await pool.query(query, [tripId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Vylet sa nenasiel' });
        }

        const trip = result.rows[0];
        trip.route = JSON.parse(trip.route); // GeoJSON string -> object
        console.log(trip.route); // Debug
        res.json({ success: true, trip });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Chyba databazy' });
    }
});

app.get('/trips', authenticateToken, async (req, res) => {
    try {
        const query = `
            SELECT t.id, u.username, t.ended_at, t.distance_km, t.duration_seconds, t.average_pace, t.title,
                ST_AsGeoJSON(t.route_geometry) AS route,
                COALESCE(json_agg(tp.photo_url) FILTER (WHERE tp.photo_url IS NOT NULL), '[]') AS photo_urls,
                (SELECT COUNT(*) FROM likes WHERE trip_id = t.id) AS likes_count,
                (SELECT COUNT(*) FROM comments WHERE trip_id = t.id) AS comments_count
            FROM trips t 
            JOIN users u ON t.user_id = u.id
            LEFT JOIN trip_photos tp ON t.id = tp.trip_id
            GROUP BY t.id, u.username, t.ended_at, t.distance_km, t.duration_seconds, t.average_pace, t.title, t.route_geometry
            LIMIT 5;
        `;
        const result = await pool.query(query);
        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Vylet sa nanasiel' });
        }

        const trips = result.rows.map(trip => {
            trip.route = JSON.parse(trip.route); // GeoJSON string -> object
            return trip;
        });

        res.json({ success: true, trips });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Chyba databazy' });
    }
});

app.get('/dailyTrips/:userId/:day', authenticateToken, async (req, res) => {
    try {
        console.log(req.params); // Debug
        const { userId, day } = req.params;
        if (isNaN(userId)) {
            return res.status(400).json({ success: false, error: 'ID používateľa musí byť číslo.' });
        }
        if (isNaN(Date.parse(day))) {
            return res.status(400).json({ success: false, error: 'Dátum je neplatný.' });
        }
        const query = `
            SELECT id, distance_km, duration_seconds, average_pace, type
            FROM trips 
            WHERE user_id = $1 
            AND started_at >= $2::date
            AND started_at < ($2::date + INTERVAL '1 day')
            ORDER BY started_at;
        `;

        const result = await pool.query(query, [userId, day]);

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Ziaden vylet v dany den' });
        }
        const trips = result.rows.map(trip => {
            return trip;
        });

        res.json({ success: true, trips });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Eror v databaze' });
    }
});

app.post('/trips', authenticateToken, async (req, res) => {
    try {
        const { userId, startedAt, endedAt, distanceKm, durationSeconds, averagePace, route, title, info, type} = req.body;

        const lineString = `LINESTRING(${route.map((p) => `${p.longitude} ${p.latitude}`).join(", ")})`;
        if (!userId || !startedAt || !endedAt || !distanceKm || !durationSeconds || !averagePace || !route || !type) {
            return res.status(400).json({ success: false, error: 'Vsetky udaje su povinne.' });
        }
        const query = `
            INSERT INTO trips (user_id, started_at, ended_at, distance_km, duration_seconds, average_pace, route_geometry, title, info, type)
            VALUES ($1, $2, $3, $4, $5, $6, ST_GeomFromText($7, 4326), $8, $9, $10)
            RETURNING id;
        `;
        if (!lineString) {
            return res.status(400).json({ success: false, error: 'Chyba pri spracovaní trasy' });
        }
        const result = await pool.query(query, [userId, startedAt, endedAt, distanceKm, durationSeconds, averagePace, lineString, title, info, type]);
        res.json({ success: true, tripId: result.rows[0].id });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Chyba databazy' });
    }
});

app.put('/auth/profile', authenticateToken, upload.single('pfp') ,async (req, res) => {
    try {
        const { userId, username, email, phoneNumber } = req.body;
        const photoUrl = `/uploads/${req.file.filename}`;
        if (!userId) {
            return res.status(400).json({ success: false, error: 'Vyžaduje sa ID používateľa.' });
        }

        const updates = [];
        const values = [userId];
        let query = 'UPDATE users SET ';

        if (username) {
            updates.push('username = $' + (values.length + 1));
            values.push(username);
        }
        if (email) {
            updates.push('email = $' + (values.length + 1));
            values.push(email);
        }
        if (phoneNumber !== undefined) {
            updates.push('tel_num = $' + (values.length + 1));
            values.push(phoneNumber === '' ? null : phoneNumber);
        }
        if (photoUrl !== undefined) {
            updates.push('photo_url = $' + (values.length + 1));
            values.push(photoUrl === '' ? null : photoUrl);
        }

        if (updates.length === 0) {
            return res.status(400).json({ success: false, error: 'Žiadne polia na aktualizáciu.' });
        }
        query += updates.join(', ') + ' WHERE id = $1 RETURNING id, username, email, tel_num, photo_url;';

        const result = await pool.query(query, values);

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, error: 'Používateľ sa nenašiel' });
        }
        res.json({ success: true, user: result.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Aktualizácia profilu zlyhala.' });
    }
});

app.put('/auth/password', authenticateToken, async (req, res) => {
    try {
        const { userId, currentPassword, newPassword } = req.body;

        if (!userId || !currentPassword || !newPassword) {
            return res.status(400).json({ success: false, error: 'Vyžaduje sa ID používateľa, aktuálne heslo a nové heslo.' });
        }
        if (newPassword.length < 8) {
            return res.status(400).json({ success: false, error: 'Heslo musí mať aspoň 8 znakov.' });
        }
        if (currentPassword === newPassword) {
            return res.status(400).json({ success: false, error: 'Nové heslo sa nesmie zhodovať s aktuálnym heslom.' });
        }
        const userQuery = await pool.query('SELECT password FROM users WHERE id = $1', [userId]);
        if (userQuery.rowCount === 0) {
            return res.status(404).json({ success: false, error: 'Používateľ sa nenašiel.' });
        }

        const user = userQuery.rows[0];

        const validPassword = await bcrypt.compare(currentPassword, user.password);
        console.log(currentPassword, user.password, validPassword); // Debug
        if (!validPassword) {
            return res.status(401).json({ success: false, error: 'Aktuálne heslo je nesprávne.' });
        }

        const hashedNewPassword = await bcrypt.hash(newPassword, 12);

        const updateQuery = `
            UPDATE users SET password = $1 WHERE id = $2 RETURNING id;
        `;
        const result = await pool.query(updateQuery, [hashedNewPassword, userId]);

        res.json({ success: true, message: 'Heslo bolo úspešne aktualizované.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Aktualizácia hesla zlyhala.' });
    }
});

app.get('/trips/:tripId/photos', authenticateToken, async (req, res) => {
    try {
        const { tripId } = req.params;

        const query = `
            SELECT id, trip_id, user_id, photo_url, latitude, longitude, description, created_at
            FROM trip_photos WHERE trip_id = $1
            ORDER BY created_at;
        `;

        const result = await pool.query(query, [tripId]);
        const photos = result.rows;
        if (photos.length === 0) {
            return res.status(404).json({ success: false, error: 'Fotografie neboli nájdené' });
        }
        res.json({ success: true, photos });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Chyba databazy' });
    }
});

app.post('/trips/:tripId/photos', authenticateToken, upload.single('photo'), async (req, res) => {
    try {
        const { tripId } = req.params;
        const { userId, latitude, longitude, description } = req.body;

        if (!req.file) {
            return res.status(400).json({ success: false, error: 'Nebola nahraná žiadna fotografia' });
        }

        if (!tripId || !userId) {
            return res.status(400).json({ success: false, error: 'Vyžaduje sa ID výletu a ID používateľa.' });
        }
        if (!latitude || !longitude) {
            return res.status(400).json({ success: false, error: 'Vyžaduje sa zemepisná šírka a dĺžka.' });
        }
        if (isNaN(latitude) || isNaN(longitude)) {
            return res.status(400).json({ success: false, error: 'Zemepisná šírka a dĺžka musia byť čísla.' });
        }
        if (description && description.length > 255) {
            return res.status(400).json({ success: false, error: 'Popis je príliš dlhý.' });
        }

        const photoUrl = `/uploads/${req.file.filename}`;

        const query = `
            INSERT INTO trip_photos (trip_id, user_id, photo_url, latitude, longitude, description, created_at)
            VALUES ($1, $2, $3, $4, $5, $6, NOW())
            RETURNING id;
        `;
        
        const result = await pool.query(query, [
            tripId, 
            userId, 
            photoUrl, 
            parseFloat(latitude), 
            parseFloat(longitude), 
            description || null
        ]);

        res.json({ 
            success: true, 
            photo: {
                id: result.rows[0].id,
                trip_id: tripId,
                user_id: userId,
                photo_url: photoUrl,
                latitude: parseFloat(latitude),
                longitude: parseFloat(longitude),
                description: description || null
            }
        });
    } catch (error) {
        console.error('Chyba pri nahrávaní fotky:', error);
        res.status(500).json({ success: false, error: 'Chyba databazy' });
    }
});

app.delete('/trips/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;

        const tripQuery = "SELECT * FROM trips WHERE id = $1";
        const tripResult = await pool.query(tripQuery, [id]);
        
        if (tripResult.rows.length === 0) {
            return res.status(404).json({ 
                success: false, 
                error: 'Výlet nebol nájdený.' 
            });
        }
        if (tripResult.rows[0].user_id !== req.user.id) {
            return res.status(403).json({ 
                success: false, 
                error: 'Nemáte oprávnenie na odstránenie tohto výletu.' 
            });
        }
        await pool.query('BEGIN');
        
        const deleteCommentsQuery = "DELETE FROM comments WHERE trip_id = $1";
        await pool.query(deleteCommentsQuery, [id]);
        
        const deleteLikesQuery = "DELETE FROM likes WHERE trip_id = $1";
        await pool.query(deleteLikesQuery, [id]);
        
        const deletePhotosQuery = "DELETE FROM trip_photos WHERE trip_id = $1";
        await pool.query(deletePhotosQuery, [id]);
        
        const deleteTripQuery = "DELETE FROM trips WHERE id = $1";
        await pool.query(deleteTripQuery, [id]);
        
        await pool.query('COMMIT');
        
        return res.status(200).json({ 
            success: true, 
            message: 'Výlet a všetky súvisiace údaje boli úspešne odstránené.' 
        });
    } catch (error) {
        await pool.query('ROLLBACK');
        console.error(error);
        return res.status(500).json({ 
            success: false, 
            error: 'Chyba servera pri odstraňovaní cesty.' 
        });
    }
});

app.get('/auth/verify', authenticateToken, (req, res) => {
  res.json({ 
    success: true, 
    message: 'Token je platny', 
    user: {
      id: req.user.id,
      email: req.user.email,
      username: req.user.username
    } 
  });
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});