const { MongoClient } = require('mongodb');

class DBClient {
  constructor() {
    this.url = `mongodb://${process.env.DB_HOST || 'localhost'}:${process.env.DB_PORT || 27017}`;
    this.dbName = process.env.DB_DATABASE || 'files_manager';
    this.client = new MongoClient(this.url, { useNewUrlParser: true, useUnifiedTopology: true });
    this.client.connect().then(() => {
      this.db = this.client.db(this.dbName);
    }).catch(err => console.error('MongoDB connection error:', err));
  }

  isAlive() {
    return this.client.isConnected();
  }

  async nbUsers() {
    const usersCollection = this.db.collection('users');
    return await usersCollection.countDocuments();
  }

  async nbFiles() {
    const filesCollection = this.db.collection('files');
    return await filesCollection.countDocuments();
  }
}

const dbClient = new DBClient();
module.exports = dbClient;
