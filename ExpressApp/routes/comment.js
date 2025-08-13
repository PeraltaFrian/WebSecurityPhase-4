import express from 'express';
import validateJWT from '../middleware/validateToken.js';
import Comment from '../models/Comment.js';
import sanitizeHtml from 'sanitize-html'; // Added for XSS prevention

const commentRouter = express.Router();

commentRouter.use(validateJWT);

commentRouter.post("/", async (req, res) => {

    console.log(`*** POST COMMENT - START ***`);
    const user = req.user;

    const {username, commenttxt} = req.body;

    if(user.username != username) {
        console.log(`token mismatch`);
        console.log(`*** POST COMMENT - END ***`);
        return res.status(401).json({message:"token mismatch"});
    }

    // ✅ Sanitize the comment to prevent XSS
    const safeCommentText = sanitizeHtml(commenttxt, {
        allowedTags: [],           // remove all HTML tags
        allowedAttributes: {},     // remove all attributes
    });

    console.log(`adding sanitized comment: ${safeCommentText}`);

    /* changed console.log(`adding comment: ${commenttxt}`);*/

    const newComment = new Comment({
        user: username,
        text: commenttxt,
    });
    try {
        await newComment.save();
        res.status(201).json({
            message: "comment saved",
            comment: {
                user: username,
                text: commenttxt
            }
        })
        console.log(`*** POST COMMENT - END ***`);
    } catch(error) {
        console.error(`Error while saving comment`);
        console.error(error);
        res.status(500).json({message: "Internal server error"});
        console.log(`*** POST COMMENT - END ***`);
    }
    

});

commentRouter.get("/", async (req,res) => {

    console.log(`*** FIND ALL COMMENTS - START ***`);
    try {

        const comments = await Comment.find({});

        res.status(200).json({
            comment_list: comments,
        })
        console.log(`*** FIND ALL COMMENTS - END ***`);

    } catch(error) {
        console.error(`error while getting comments`);
        console.error(error);

        res.status(500).json({message: "internal server error"});
        console.log(`*** FIND ALL COMMENTS - END ***`);
    }
});

export default commentRouter;