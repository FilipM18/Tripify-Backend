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

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});