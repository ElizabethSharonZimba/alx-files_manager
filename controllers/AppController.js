const redisClient = require('../utils/redis');
const dbClient = require('../utils/db');

exports.getStatus = async (req, res) => {
  res.status(200).json({
    redis: redisClient.isAlive(),
    db: dbClient.isAlive()
  });
};

exports.getStats = async (req, res) => {
  const usersCount = await dbClient.nbUsers();
  const filesCount = await dbClient.nbFiles();
  res.status(200).json({
    users: usersCount,
    files: filesCount
  });
};
