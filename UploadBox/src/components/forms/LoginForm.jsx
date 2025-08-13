import { useState } from 'react';
import { useNavigate } from "react-router-dom";
import './Form.css';
import { useLoggedInUserContext } from '../../context/LoggedInUserContext';
import { isDefaultUser } from '../../model/user.js';
const LoginForm = () => {

    const loggedInUserContext = useLoggedInUserContext();
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');

    const navigate = useNavigate();

    // Sanitize helper
    const sanitizeText = (input) => input.trim().replace(/[<>\/\\]/g, '');

    // Validation helper
    const isValidUsername = (username) => /^[a-zA-Z0-9_]{3,20}$/.test(username);


    async function handleSubmit(event) {
        console.log("HandleSubmit");
        event.preventDefault();

        const cleanUsername = sanitizeText(username);
        const cleanPassword = password;

        if (!isValidUsername(cleanUsername)) {
            alert('Username must be 3–20 characters and use only letters, numbers, or underscores.');
            return;
        }

        /* loggedInUserContext.loginFunc(username, password);*/
        loggedInUserContext.loginFunc(cleanUsername, cleanPassword);
        navigate('/')
        
    }
    return (
        <>
            {
                isDefaultUser(loggedInUserContext.loggedInUser)
                ?
                <section id="form-section">
                    <h2 className='title'>Login</h2>
                    <form>
                        <input 
                            //autoComplete='false' 
                            autoComplete='off' 
                            id='username' 
                            className='form-input' 
                            //type="string" 
                            type="text" 
                            required 
                            placeholder="Username" 
                            maxLength={50}
                            value={username}
                            //onChange={(event) => {
                                // TODO: update to add validation
                            //    setUsername(event.target.value)
                            onChange={(event) => {
                                const cleanValue = sanitizeText(event.target.value);
                                setUsername(cleanValue);
                            }}
                        />
                        <input 
                            autoComplete='false' 
                            id='password' 
                            className='form-input' 
                            type="password" 
                            required 
                            placeholder="Password" 
                            value={password}
                            onChange={(event) => {
                                // TODO: update to add validation
                                setPassword(event.target.value);
                            }}
                        />
                        <input className='btn' id='form-submit' type="submit" onClick={handleSubmit}/>
                    </form>
                    <p id="no-account">Don't have a account? <span onClick={() => navigate('/register')}>Register here</span></p>
                </section>
                :
                navigate('/')
            }
        </>
        
    );
}

export default LoginForm;