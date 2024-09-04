const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const dbClient = require('../utils/db');
const redisClient = require('../utils/redis');

const FOLDER_PATH = process.env.FOLDER_PATH || '/tmp/files_manager';

exports.postUpload = async (req, res) => {
  const token = req.headers['x-token'];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  const userId = await redisClient.get(`auth_${token}`);
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });

  const { name, type, parentId = 0, isPublic = false, data } = req.body;

  if (!name) return res.status(400).json({ error: 'Missing name' });
  if (!type) return res.status(400).json({ error: 'Missing type' });
  if (type !== 'folder' && !data) return res.status(400).json({ error: 'Missing data' });

  const filesCollection = dbClient.db.collection('files');
  if (parentId !== 0) {
    const parentFile = await filesCollection.findOne({ _id: parentId });
    if (!parentFile) return res.status(400).json({ error: 'Parent not found' });
    if (parentFile.type !== 'folder') return res.status(400).json({ error: 'Parent is not a folder' });
  }

  const fileId = new crypto.randomUUID();
  const filePath = type === 'folder' ? null : path.join(FOLDER_PATH, fileId);
  if (type !== 'folder' && !fs.existsSync(FOLDER_PATH)) fs.mkdirSync(FOLDER_PATH, { recursive: true });
  if (type !== 'folder' && data) fs.writeFileSync(filePath, Buffer.from(data, 'base64'));

  const fileDoc = {
    userId,
    name,
    type,
    isPublic,
    parentId,
    localPath: filePath || null
  };
  const result = await filesCollection.insertOne(fileDoc);

  res.status(201).json({ id: result.insertedId, ...fileDoc });
};
