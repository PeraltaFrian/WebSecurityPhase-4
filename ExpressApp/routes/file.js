import express from 'express';
import multer from 'multer';
import File from '../models/File.js';
import validateJWT from '../middleware/validateToken.js';
import canAccessFile from '../middleware/authorization.js';


const fileRouter = express.Router();

fileRouter.use(validateJWT);

const upload = multer({dest: 'uploads/'});

// Sanitize filename function 
const sanitizeFileName = (filename) => {
  return filename.replace(/[^a-zA-Z0-9_.-]/g, '_');
};

fileRouter.post('/', 
    upload.single('file'),
    async (req, res) => {
        console.log(`*** FILE UPLOAD - START ***`);

        if (!req.file) {
            return res.status(400).json({ message: "No file uploaded" });
        }

        // Sanitize the original file name
        const unsafeFilename = req.file.originalname;
        const sanitizedFilename = sanitizeFileName(unsafeFilename);

        const file = new File({
            /** changed filename: req.file.originalname, */
            filename: sanitizedFilename,
            path: req.file.path,
            uploadedBy: req.user.username,
            department: req.user.department
        });
        try {
            await file.save();
            res.status(201).json({
                message: 'file uploaded',
                file
            });
        } catch (error) {
      console.error('Error saving file:', error);
      return res.status(500).json({ message: 'Internal server error' });
    }
        console.log(`*** FILE UPLOAD - END ***`);
    }
);

fileRouter.get('/:id', async (req, res) => {
    console.log(`*** FIND FILE - START ***`);
    const file = await File.findById(req.params.id);
    if(!file) {
        console.log(`no file found`);
        console.log(`*** FIND FILE - END ***`);
        return res.status(404).json({
            message: 'not found',
        });
    }

    if(!canAccessFile(req.user, file)) {
        console.log(`file access denied`);
        console.log(`*** FIND FILE - END ***`);
        return res.status(400).json({message: "access denied"});
    }

    console.log(`*** FIND FILE - END ***`);
    res.sendFile(file.path, {root: '.'});
})

fileRouter.get('/', async(req, res) => {

    console.log(`*** FIND ALL FILE - START ***`);

    console.log(`User: ${req.user.username}`)
    console.log(`Department: ${req.user.department}`);
    let files = null;
    if(req.user.role === 'admin') {
        files = await File.find({});
    } else {
        const department = req.user.department;
        files = await File.find({department: department})
    }

    if( files !== null) {
        console.log(`number of files found: ${files.length}`);
        res.status(200).json({
            files_data: files
        })
        console.log(`*** FIND ALL FILE - END ***`);
    } else {
        console.log(`Something went wrong, Check!!!`);
        res.status(200).json({
            files_data: []
        })
        console.log(`*** FIND ALL FILE - END ***`);
    }
    
});


export default fileRouter;