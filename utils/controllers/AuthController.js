const crypto = require('crypto');
const redisClient = require('../utils/redis');
const dbClient = require('../utils/db');
const { v4: uuidv4 } = require('uuid');

exports.getConnect = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

  const [email, password] = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
  const hashedPassword = crypto.createHash('sha1').update(password).digest('hex');

  const usersCollection = dbClient.db.collection('users');
  const user = await usersCollection.findOne({ email, password: hashedPassword });

  if (!user) return res.status(401).json({ error: 'Unauthorized' });

  const token = uuidv4();
  await redisClient.set(`auth_${token}`, user._id.toString(), 86400); // 24 hours

  res.status(200).json({ token });
};

exports.getDisconnect = async (req, res) => {
  const token = req.headers['x-token'];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const result = await redisClient.del(`auth_${token}`);
  if (result === 1) {
    res.status(204).send();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};const crypto = require('crypto');
const redisClient = require('../utils/redis');
const dbClient = require('../utils/db');
const { v4: uuidv4 } = require('uuid');

exports.getConnect = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

  const [email, password] = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
  const hashedPassword = crypto.createHash('sha1').update(password).digest('hex');

  const usersCollection = dbClient.db.collection('users');
  const user = await usersCollection.findOne({ email, password: hashedPassword });

  if (!user) return res.status(401).json({ error: 'Unauthorized' });

  const token = uuidv4();
  await redisClient.set(`auth_${token}`, user._id.toString(), 86400); // 24 hours

  res.status(200).json({ token });
};

exports.getDisconnect = async (req, res) => {
  const token = req.headers['x-token'];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const result = await redisClient.del(`auth_${token}`);
  if (result === 1) {
    res.status(204).send();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};const crypto = require('crypto');
const redisClient = require('../utils/redis');
const dbClient = require('../utils/db');
const { v4: uuidv4 } = require('uuid');

exports.getConnect = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

  const [email, password] = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
  const hashedPassword = crypto.createHash('sha1').update(password).digest('hex');

  const usersCollection = dbClient.db.collection('users');
  const user = await usersCollection.findOne({ email, password: hashedPassword });

  if (!user) return res.status(401).json({ error: 'Unauthorized' });

  const token = uuidv4();
  await redisClient.set(`auth_${token}`, user._id.toString(), 86400); // 24 hours

  res.status(200).json({ token });
};

exports.getDisconnect = async (req, res) => {
  const token = req.headers['x-token'];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const result = await redisClient.del(`auth_${token}`);
  if (result === 1) {
    res.status(204).send();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};const crypto = require('crypto');
const redisClient = require('../utils/redis');
const dbClient = require('../utils/db');
const { v4: uuidv4 } = require('uuid');

exports.getConnect = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

  const [email, password] = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
  const hashedPassword = crypto.createHash('sha1').update(password).digest('hex');

  const usersCollection = dbClient.db.collection('users');
  const user = await usersCollection.findOne({ email, password: hashedPassword });

  if (!user) return res.status(401).json({ error: 'Unauthorized' });

  const token = uuidv4();
  await redisClient.set(`auth_${token}`, user._id.toString(), 86400); // 24 hours

  res.status(200).json({ token });
};

exports.getDisconnect = async (req, res) => {
  const token = req.headers['x-token'];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const result = await redisClient.del(`auth_${token}`);
  if (result === 1) {
    res.status(204).send();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};const crypto = require('crypto');
const redisClient = require('../utils/redis');
const dbClient = require('../utils/db');
const { v4: uuidv4 } = require('uuid');

exports.getConnect = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

  const [email, password] = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
  const hashedPassword = crypto.createHash('sha1').update(password).digest('hex');

  const usersCollection = dbClient.db.collection('users');
  const user = await usersCollection.findOne({ email, password: hashedPassword });

  if (!user) return res.status(401).json({ error: 'Unauthorized' });

  const token = uuidv4();
  await redisClient.set(`auth_${token}`, user._id.toString(), 86400); // 24 hours

  res.status(200).json({ token });
};

exports.getDisconnect = async (req, res) => {
  const token = req.headers['x-token'];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const result = await redisClient.del(`auth_${token}`);
  if (result === 1) {
    res.status(204).send();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};const crypto = require('crypto');
const redisClient = require('../utils/redis');
const dbClient = require('../utils/db');
const { v4: uuidv4 } = require('uuid');

exports.getConnect = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

  const [email, password] = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
  const hashedPassword = crypto.createHash('sha1').update(password).digest('hex');

  const usersCollection = dbClient.db.collection('users');
  const user = await usersCollection.findOne({ email, password: hashedPassword });

  if (!user) return res.status(401).json({ error: 'Unauthorized' });

  const token = uuidv4();
  await redisClient.set(`auth_${token}`, user._id.toString(), 86400); // 24 hours

  res.status(200).json({ token });
};

exports.getDisconnect = async (req, res) => {
  const token = req.headers['x-token'];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const result = await redisClient.del(`auth_${token}`);
  if (result === 1) {
    res.status(204).send();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};const crypto = require('crypto');
const redisClient = require('../utils/redis');
const dbClient = require('../utils/db');
const { v4: uuidv4 } = require('uuid');

exports.getConnect = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

  const [email, password] = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
  const hashedPassword = crypto.createHash('sha1').update(password).digest('hex');

  const usersCollection = dbClient.db.collection('users');
  const user = await usersCollection.findOne({ email, password: hashedPassword });

  if (!user) return res.status(401).json({ error: 'Unauthorized' });

  const token = uuidv4();
  await redisClient.set(`auth_${token}`, user._id.toString(), 86400); // 24 hours

  res.status(200).json({ token });
};

exports.getDisconnect = async (req, res) => {
  const token = req.headers['x-token'];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const result = await redisClient.del(`auth_${token}`);
  if (result === 1) {
    res.status(204).send();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};const crypto = require('crypto');
const redisClient = require('../utils/redis');
const dbClient = require('../utils/db');
const { v4: uuidv4 } = require('uuid');

exports.getConnect = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

  const [email, password] = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
  const hashedPassword = crypto.createHash('sha1').update(password).digest('hex');

  const usersCollection = dbClient.db.collection('users');
  const user = await usersCollection.findOne({ email, password: hashedPassword });

  if (!user) return res.status(401).json({ error: 'Unauthorized' });

  const token = uuidv4();
  await redisClient.set(`auth_${token}`, user._id.toString(), 86400); // 24 hours

  res.status(200).json({ token });
};

exports.getDisconnect = async (req, res) => {
  const token = req.headers['x-token'];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const result = await redisClient.del(`auth_${token}`);
  if (result === 1) {
    res.status(204).send();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};const crypto = require('crypto');
const redisClient = require('../utils/redis');
const dbClient = require('../utils/db');
const { v4: uuidv4 } = require('uuid');

exports.getConnect = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Unauthorized' });

  const [email, password] = Buffer.from(authHeader.split(' ')[1], 'base64').toString().split(':');
  const hashedPassword = crypto.createHash('sha1').update(password).digest('hex');

  const usersCollection = dbClient.db.collection('users');
  const user = await usersCollection.findOne({ email, password: hashedPassword });

  if (!user) return res.status(401).json({ error: 'Unauthorized' });

  const token = uuidv4();
  await redisClient.set(`auth_${token}`, user._id.toString(), 86400); // 24 hours

  res.status(200).json({ token });
};

exports.getDisconnect = async (req, res) => {
  const token = req.headers['x-token'];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const result = await redisClient.del(`auth_${token}`);
  if (result === 1) {
    res.status(204).send();
  } else {
    res.status(401).json({ error: 'Unauthorized' });
  }
};
