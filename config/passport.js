const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');
const mongoose = require('mongoose');
const User = require('../models/User'); // Ensure this path is correct

const opts = {
    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: process.env.JWT_SECRET,
};

module.exports = (passport) => {
    console.log('Passport config loaded');

    passport.use(
        new JwtStrategy(opts, async (jwt_payload, done) => {
            

            try {
                const user = await User.findById(jwt_payload.user.id); 
                if (user) {
                    
                    return done(null, user);
                }
                console.log('User not found');
                return done(null, false);
            } catch (err) {
                console.error('Error in JWT strategy:', err.message);
                return done(err, false);
            }
        })
    );
};
