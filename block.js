// Importation des bibliothèques nécessaires
const crypto = require('crypto');
const QRCode = require('qrcode'); // Bibliothèque pour générer des QR codes
const EC = require('elliptic').ec; // Bibliothèque elliptic pour ECDSA

// Intervalle de temps minimal (en millisecondes) entre chaque bloc
const TIME_BLOCK = 10000; // 10 secondes

// Classe pour gérer les notifications
class NotificationManager {
    constructor() {
        this.subscribers = {}; // Dictionnaire pour stocker les abonnés aux notifications
    }

    // Méthode pour ajouter un abonné
    subscribe(userId, callback) {
        if (!this.subscribers[userId]) {
            this.subscribers[userId] = [];
        }
        this.subscribers[userId].push(callback);
    }

    // Méthode pour envoyer des notifications
    notify(userId, message) {
        if (this.subscribers[userId]) {
            this.subscribers[userId].forEach(callback => callback(message)); // Appelle chaque fonction de rappel
        }
    }
}

// Classe pour gérer les requêtes avec protection contre les attaques DDoS
class RateLimiter {
    constructor(limit, interval) {
        this.limit = limit; // Limite de requêtes
        this.interval = interval; // Intervalle de temps en millisecondes
        this.requests = {}; // Stocke les timestamps des requêtes
    }

    isAllowed(userId) {
        const now = Date.now();
        if (!this.requests[userId]) {
            this.requests[userId] = [];
        }
        // Filtre les requêtes anciennes
        this.requests[userId] = this.requests[userId].filter(timestamp => timestamp > now - this.interval);

        if (this.requests[userId].length < this.limit) {
            this.requests[userId].push(now); // Ajoute le timestamp de la requête
            return true; // Autorise la requête
        }
        return false; // Refuse la requête
    }
}

// Classe pour gérer les transactions
class Transaction {
    constructor(fromAddress, toAddress, amount) {
        this.fromAddress = fromAddress;
        this.toAddress = toAddress;
        this.amount = amount;
        this.timestamp = Date.now();
        this.encryptedData = null; // Ajout d'un champ pour les données chiffrées
    }

    // Méthode pour générer un QR code pour la transaction
    generateQRCode() {
        const transactionData = JSON.stringify(this);
        QRCode.toDataURL(transactionData, (err, url) => {
            if (err) {
                console.error('Erreur de génération du QR code :', err);
                return;
            }
            console.log(`QR Code pour la transaction de ${this.amount} de ${this.fromAddress} à ${this.toAddress} : ${url}`);
        });
    }

    // Méthode pour chiffrer les données de la transaction avec AES-256
    encryptData(secretKey) {
        const iv = crypto.randomBytes(16); // Génération d'un vecteur d'initialisation
        const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secretKey, 'hex'), iv);
        let encrypted = cipher.update(JSON.stringify(this), 'utf8', 'hex');
        encrypted += cipher.final('hex');
        this.encryptedData = iv.toString('hex') + ':' + encrypted; // Stockage de l'IV avec les données chiffrées
    }

    // Méthode pour déchiffrer les données de la transaction
    static decryptData(encryptedData, secretKey) {
        const parts = encryptedData.split(':');
        const iv = Buffer.from(parts.shift(), 'hex');
        const encryptedText = Buffer.from(parts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(secretKey, 'hex'), iv);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return JSON.parse(decrypted);
    }
}

// Classe pour gérer les signatures numériques
class SignatureManager {
    constructor() {
        this.ec = new EC('secp256k1'); // Utilise la courbe secp256k1
    }

    // Génération d'une paire de clés
    generateKeyPair() {
        const key = this.ec.genKeyPair();
        return {
            privateKey: key.getPrivate('hex'),
            publicKey: key.getPublic('hex')
        };
    }

    // Signature d'un message
    signMessage(message, privateKey) {
        const key = this.ec.keyFromPrivate(privateKey, 'hex');
        return key.sign(message).toDER('hex');
    }

    // Vérification de la signature d'un message
    verifySignature(message, signature, publicKey) {
        const key = this.ec.keyFromPublic(publicKey, 'hex');
        return key.verify(message, signature);
    }
}

// Classe DigitalIdentity pour gérer les identités numériques décentralisées
class DigitalIdentity {
    constructor() {
        this.ec = new EC('secp256k1');
    }

    // Méthode pour générer une nouvelle identité numérique
    createIdentity() {
        const key = this.ec.genKeyPair();
        return {
            privateKey: key.getPrivate('hex'),
            publicKey: key.getPublic('hex'),
            did: this.generateDID(key.getPublic('hex'))
        };
    }

    // Méthode pour générer un DID unique basé sur la clé publique
    generateDID(publicKey) {
        return `did:blockchain:${crypto.createHash('sha256').update(publicKey).digest('hex')}`;
    }

    // Méthode pour vérifier l'identité numérique en utilisant une signature
    verifyIdentity(did, message, signature) {
        const publicKey = this.extractPublicKeyFromDID(did);
        const key = this.ec.keyFromPublic(publicKey, 'hex');
        return key.verify(message, signature);
    }

    // Extraire la clé publique d'un DID
    extractPublicKeyFromDID(did) {
        return did.split(':')[2];
    }
}

// Classe Block pour représenter un bloc dans la blockchain
class Block {
    constructor(index, timestamp, transactions, previousHash = '', authoritySignature = '', digitalSignature = '') {
        this.index = index;
        this.timestamp = timestamp;
        this.transactions = transactions;
        this.previousHash = previousHash;
        this.authoritySignature = authoritySignature;
        this.digitalSignature = digitalSignature;
        this.hash = this.calculateHash();
    }

    calculateHash() {
        return crypto.createHash('sha256')
            .update(this.index + this.previousHash + this.timestamp + JSON.stringify(this.transactions) + this.authoritySignature + this.digitalSignature)
            .digest('hex');
    }

    isValid(authority) {
        return authority.isAuthorized(this.authoritySignature);
    }

    verifyDigitalSignature(signatureManager, publicKey) {
        return signatureManager.verifySignature(this.hash, this.digitalSignature, publicKey);
    }
}

// Classe Authority pour gérer la preuve d'autorité
class Authority {
    constructor() {
        this.authorizedValidators = new Set();
    }

    addValidator(validator) {
        this.authorizedValidators.add(validator);
    }

    isAuthorized(validator) {
        return this.authorizedValidators.has(validator);
    }
}

// Classe Blockchain pour gérer la chaîne de blocs
class Blockchain {
    constructor() {
        this.chain = [this.createGenesisBlock()];
        this.authority = new Authority();
        this.signatureManager = new SignatureManager();
        this.digitalIdentity = new DigitalIdentity(); // Instance de DigitalIdentity
        this.identities = {}; // Stockage des identités numériques
        this.pendingTransactions = [];
        this.notificationManager = new NotificationManager(); // Instance de NotificationManager
        this.rateLimiter = new RateLimiter(10, 60000); // Limite de 10 requêtes par minute
        this.cache = new Map(); // Mise en cache des transactions
    }

    createGenesisBlock() {
        const transactions = [];
        return new Block(0, Date.now(), transactions, "0", "validator1", "");
    }

    getLatestBlock() {
        return this.chain[this.chain.length - 1];
    }

    synchronizeTimestamp(newBlock) {
        const neighborTimestamps = [];
        if (this.chain.length > 1) {
            const previousBlock = this.chain[this.chain.length - 2];
            neighborTimestamps.push(previousBlock.timestamp);
        }

        if (this.chain.length > 2) {
            const secondPreviousBlock = this.chain[this.chain.length - 3];
            neighborTimestamps.push(secondPreviousBlock.timestamp);
        }

        if (neighborTimestamps.length > 0) {
            const avgTimestamp = neighborTimestamps.reduce((a, b) => a + b, 0) / neighborTimestamps.length;
            newBlock.timestamp = Math.round(avgTimestamp);
        }
    }

    addTransaction(transaction, secretKey) {
        // Vérifie si la requête est autorisée
        if (!this.rateLimiter.isAllowed(transaction.fromAddress)) {
            console.log("Trop de requêtes. Veuillez réessayer plus tard.");
            return;
        }

        // Vérifie si la transaction est déjà dans le cache
        const cacheKey = `${transaction.fromAddress}-${transaction.toAddress}-${transaction.amount}`;
        if (this.cache.has(cacheKey)) {
            console.log("Transaction déjà ajoutée au cache.");
            return;
        }

        transaction.encryptData(secretKey); // Chiffrement des données de la transaction
        this.pendingTransactions.push(transaction);
        this.cache.set(cacheKey, transaction); // Ajoute la transaction au cache

        // Notification à tous les abonnés
        this.notificationManager.notify(transaction.fromAddress, `Transaction de ${transaction.amount} à ${transaction.toAddress} ajoutée.`);
    }

    minePendingTransactions(authority) {
        if (this.pendingTransactions.length === 0) {
            console.log("Aucune transaction en attente.");
            return;
        }

        const latestBlock = this.getLatestBlock();
        const newBlock = new Block(latestBlock.index + 1, Date.now(), this.pendingTransactions, latestBlock.hash);

        // Signature de la transaction par l'autorité
        newBlock.authoritySignature = this.signatureManager.signMessage(newBlock.hash, authority.privateKey);
        
        // Signature numérique pour le bloc
        const userKey = this.digitalIdentity.createIdentity(); // Crée une nouvelle identité pour l'utilisateur
        this.identities[authority.did] = userKey; // Stocke l'identité
        newBlock.digitalSignature = this.signatureManager.signMessage(newBlock.hash, userKey.privateKey); // Signature numérique du bloc

        // Synchronisation du timestamp
        this.synchronizeTimestamp(newBlock);

        this.chain.push(newBlock);
        this.pendingTransactions = [];
        console.log(`Bloc ${newBlock.index} miné et ajouté à la chaîne.`);
    }

    verifyTransaction(transaction) {
        const decryptedTransaction = Transaction.decryptData(transaction.encryptedData, secretKey);
        const publicKey = this.identities[transaction.fromAddress].publicKey; // Récupère la clé publique de l'identité
        return this.signatureManager.verifySignature(decryptedTransaction.hash, transaction.digitalSignature, publicKey);
    }
}

// Utilisation de la Blockchain
const myBlockchain = new Blockchain();
const secretKey = crypto.randomBytes(32).toString('hex'); // Génération d'une clé secrète pour AES-256
const userAuthority = myBlockchain.digitalIdentity.createIdentity(); // Créer une identité pour l'autorité

// Exemple d'ajout d'une transaction
const transaction1 = new Transaction(userAuthority.did, 'destinationAddress', 100);
transaction1.generateQRCode(); // Génération du QR code
myBlockchain.addTransaction(transaction1, secretKey); // Ajout de la transaction à la blockchain

// Exemple de minage des transactions
myBlockchain.minePendingTransactions(userAuthority);