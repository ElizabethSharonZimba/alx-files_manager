const crypto = require('crypto');
const dbClient = require('../utils/db');

exports.postNew = async (req, res) => {
  const { email, password } = req.body;
  if (!email) return res.status(400).json({ error: 'Missing email' });
  if (!password) return res.status(400).json({ error: 'Missing password' });

  const usersCollection = dbClient.db.collection('users');
  const existingUser = await usersCollection.findOne({ email });
  if (existingUser) return res.status(400).json({ error: 'Already exist' });

  const hashedPassword = crypto.createHash('sha1').update(password).digest('hex');
  const result = await usersCollection.insertOne({ email, password: hashedPassword });

  res.status(201).json({ id: result.insertedId, email });
};
