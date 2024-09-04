
import Bull from 'bull';
import fs from 'fs';
import imageThumbnail from 'image-thumbnail';
import dbClient from './utils/db';

const fileQueue = new Bull('fileQueue');

fileQueue.process(async (job) => {
    const { fileId, userId } = job.data;

    if (!fileId) {
        throw new Error('Missing fileId');
    }
    if (!userId) {
        throw new Error('Missing userId');
    }

    const file = await dbClient.db.collection('files').findOne({ _id: dbClient.objectId(fileId), userId });

    if (!file) {
        throw new Error('File not found');
    }

    if (file.type === 'image') {
        const sizes = [500, 250, 100];
        for (const size of sizes) {
            const thumbnail = await imageThumbnail(file.localPath, { width: size });
            const thumbnailPath = `${file.localPath}_${size}`;
            fs.writeFileSync(thumbnailPath, thumbnail);
        }
    }
});
