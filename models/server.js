const express = require("express");
const { MongoClient, ServerApiVersion } = require('mongodb');
const cors = require('cors');
//const bcrypt = require('bcrypt'); // Para encriptar contraseñas
const jwt = require('jsonwebtoken'); // Para manejar JWT
const bodyParser = require('body-parser'); // Para manejar datos JSON en las solicitudes

const uri = "mongodb+srv://Azumarill:Azumarill@cluster0.cl3vl.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";
const jwtSecret = process.env.JWT_SECRET || 'default_secret'; // Usa una variable de entorno

class Server {
    constructor(){
        this.app = express();
        this.port = process.env.PORT || 5000;
        this.client = null;
        this.conectarMongo();
        this.middlewares();
        this.routes();
        this.listen();
    }

    async conectarMongo(){
        const client = new MongoClient(uri, {
            serverApi: {
                version: ServerApiVersion.v1,
                strict: true,
                deprecationErrors: true,
            }
        });

        try {
            await client.connect();
            this.client = client;
            console.log("Conexión exitosa a MongoDB Atlas");
        } catch (error) {
            console.error("Error al conectar a MongoDB:", error);
        }
    }

    middlewares(){
        this.app.use(cors({
            origin: '*', // O el dominio específico de tu aplicación
            methods: ['GET', 'POST'],
            allowedHeaders: ['Content-Type', 'Authorization']
        }));
        this.app.use(bodyParser.json()); // Para manejar datos JSON en las solicitudes
        this.app.use(express.static('public'));
    }

    routes(){
        // Ruta para registrar un nuevo usuario
        /*this.app.post('/register', async (req, res) => {
            const { username, password, role } = req.body;
            if (!username || !password || !role) {
                return res.status(400).send("Todos los campos son requeridos");
            }

            try {
                const hashedPassword = await bcrypt.hash(password, 10);
                const database = this.client.db("iluminacion");
                const collection = database.collection("usuarios");
                const result = await collection.insertOne({ username, password: hashedPassword, role });
                res.status(201).json({ message: 'Usuario registrado con éxito', userId: result.insertedId });
            } catch (error) {
                console.error("Error al registrar usuario:", error);
                res.status(500).send("Error al registrar usuario");
            }
        });*/

        // Ruta para el inicio de sesión
        /*this.app.post('/login', async (req, res) => {
            const { username, password } = req.body;
            if (!username || !password) {
                return res.status(400).send("Username y password son requeridos");
            }

            try {
                const database = this.client.db("iluminacion");
                const collection = database.collection("usuarios");
                const user = await collection.findOne({ username });

                if (user && await bcrypt.compare(password, user.password)) {
                    const token = jwt.sign({ userId: user._id, role: user.role }, jwtSecret, { expiresIn: '1h' });
                    res.status(200).json({ token });
                } else {
                    res.status(401).send("Credenciales inválidas");
                }
            } catch (error) {
                console.error("Error al iniciar sesión:", error);
                res.status(500).send("Error al iniciar sesión");
            }
        });*/

        // Rutas protegidas por autenticación
        this.app.get('/autos', this.verifyToken, this.verifyRole('user', 'admin'), async (req, res) => {
            try {
                const database = this.client.db("DesMovil");
                const collection = database.collection("autos");
                const results = await collection.find({}).toArray();
                res.json(results);
            } catch (error) {
                console.error("Error en la consulta:", error);
                res.status(500).send("Error en la consulta");
            }
        });

        this.app.get('/luz', this.verifyToken, this.verifyRole('user', 'admin'), async (req, res) => {
            try {
                const database = this.client.db("iluminacion");
                const collection = database.collection("luz");
                const results = await collection.find({}).toArray();
                res.json(results);
            } catch (error) {
                console.error("Error en la consulta:", error);
                res.status(500).send("Error en la consulta");
            }
        });
    }

    // Middleware para verificar el token JWT
    // Middleware para verificar el token JWT
    verifyToken(req, res, next) {
        const token = req.headers['authorization'];
        if (!token) {
        return res.status(403).send("Token requerido");
        }
        try {
        const decoded = jwt.verify(token.split(" ")[1], jwtSecret);
        req.user = decoded;
        next();
        } catch (error) {
        res.status(401).send("Token inválido");
        }
    }


    // Middleware para verificar el rol del usuario
    verifyRole(...roles) {
        return (req, res, next) => {
            if (req.user && roles.includes(req.user.role)) {
                next();
            } else {
                res.status(403).send("Acceso denegado");
            }
        };
    }

    listen(){
        this.app.listen(this.port, (err) => {
            if(err) {
                console.log(err);
            }
            console.log(`Servidor corriendo en http://127.0.0.1:${this.port}`);
        });
    }
}

module.exports = Server;
