import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken'; // Bude treba pridat
import dotenv from 'dotenv';
import pkg from '@supabase/pg';
const { Pool } = pkg;

dotenv.config();
const app = express();
const port = 3000;

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

// Debug !nezabudni vymazat
app.use((req, res, next) => {
    console.log('Req body:', req.body);
    console.log('Content-Type:', req.get('Content-Type'));
    next();
});

app.post('/auth/register', async (req, res) => {
    try {
        const { username, email, password, phoneNumber, photoUrl } = req.body;

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
        const sanitizedPhotoUrl = photoUrl === '' ? null : photoUrl;

        const hashedPassword = await bcrypt.hash(password, 12);

        const query = `
            INSERT INTO users (username, email, password, tel_num, photo_url)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, username, email;
        `;
        const result = await pool.query(query, [username, email, hashedPassword, sanitizedPhoneNumber, sanitizedPhotoUrl]);

        const newUser = result.rows[0];
        res.json({ success: true, user: newUser });
    } catch (error) {
        if (error.code === '23505') { // Unique constraint violation
            return res.status(409).json({ success: false, error: 'Pouzivatel uz existuje' });
        }
        console.error(error);
        res.status(500).json({ success: false, error: 'Registracia zlyhala' });
    }
});

app.post('/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const userQuery = await pool.query('SELECT id, email, password FROM users WHERE email = $1', [email]);
        if (userQuery.rowCount === 0) return res.status(401).json({ success: false, error: 'Invalidne udaje' });

        const user = userQuery.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ success: false, error: 'Invalidne udaje' });

        res.json({ success: true , userId: user.id, email: user.email });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Prihlasenie zlyhalo' });
    }
});

app.get('/likes/:tripId', async (req, res) => {
    try {
        console.log(req.params);
        const { tripId } = req.params;

        const query = `
                SELECT user_id
                FROM likes WHERE trip_id = $1;
            `;
        const result = await pool.query(query, [tripId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, error: 'Vylet nebol najdeny' });
        }
        const likes = result.rows.map(row => row.user_id);
        console.log(likes);
        res.json({ success: true, likes });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Chyba databazy' });
    }
});

app.get('/comments/:tripId', async (req, res) => {    
    try {
        console.log(req.params);
        const { tripId } = req.params;

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

app.get('/trips/:tripId', async (req, res) => {
    try {
        console.log(req.params); // Debug
        const { tripId } = req.params;

        const query = `
            SELECT t.id, u.username, t.ended_at, t.distance_km, t.duration_seconds, t.average_pace, t.info,
                ST_AsGeoJSON(t.route_geometry) AS route,
                COALESCE(json_agg(tp.photo_url) FILTER (WHERE tp.photo_url IS NOT NULL), '[]') AS photo_urls,
                (SELECT COUNT(*) FROM likes WHERE trip_id = t.id) AS likes_count,
                (SELECT COUNT(*) FROM comments WHERE trip_id = t.id) AS comments_count
            FROM trips t 
            JOIN users u ON t.user_id = u.id
            LEFT JOIN trip_photos tp ON t.id = tp.trip_id
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

app.get('/trips', async (req, res) => {
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

app.post('/trips', async (req, res) => {
    try {
        const { userId, startedAt, endedAt, distanceKm, durationSeconds, averagePace, route } = req.body;

        const lineString = `LINESTRING(${route.map((p) => `${p.longitude} ${p.latitude}`).join(", ")})`;

        const query = `
            INSERT INTO trips (user_id, started_at, ended_at, distance_km, duration_seconds, average_pace, route_geometry)
            VALUES ($1, $2, $3, $4, $5, $6, ST_GeomFromText($7, 4326))
            RETURNING id;
        `;

        const result = await pool.query(query, [userId, startedAt, endedAt, distanceKm, durationSeconds, averagePace, lineString]);
        res.json({ success: true, tripId: result.rows[0].id });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Database error' });
    }
});

app.put('/auth/profile', async (req, res) => {
    try {
        const { userId, username, email, phoneNumber, photoUrl } = req.body;

        if (!userId) {
            return res.status(400).json({ success: false, error: 'User ID is required.' });
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
            return res.status(400).json({ success: false, error: 'No fields to update.' });
        }

        query += updates.join(', ') + ' WHERE id = $1 RETURNING id, username, email, tel_num, photo_url;';

        const result = await pool.query(query, values);

        if (result.rowCount === 0) {
            return res.status(404).json({ success: false, error: 'User not found.' });
        }

        res.json({ success: true, user: result.rows[0] });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Profile update failed.' });
    }
});

pp.put('/auth/password', async (req, res) => {
    try {
        const { userId, currentPassword, newPassword } = req.body;

        if (!userId || !currentPassword || !newPassword) {
            return res.status(400).json({ success: false, error: 'User ID, current password, and new password are required.' });
        }

        const userQuery = await pool.query('SELECT password FROM users WHERE id = $1', [userId]);
        if (userQuery.rowCount === 0) {
            return res.status(404).json({ success: false, error: 'User not found.' });
        }

        const user = userQuery.rows[0];

        const validPassword = await bcrypt.compare(currentPassword, user.password);
        console.log(currentPassword, user.password, validPassword); // Debug
        if (!validPassword) {
            return res.status(401).json({ success: false, error: 'Current password is incorrect.' });
        }

        const hashedNewPassword = await bcrypt.hash(newPassword, 12);

        const updateQuery = `
            UPDATE users SET password = $1 WHERE id = $2 RETURNING id;
        `;
        const result = await pool.query(updateQuery, [hashedNewPassword, userId]);

        res.json({ success: true, message: 'Password updated successfully.' });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, error: 'Password update failed.' });
    }
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});