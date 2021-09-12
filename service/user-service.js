const UserDto = require('../dtos/user-dto');
const UserModel = require('../models/user-model');
const bcrypt = require('bcrypt');
const uuid = require('uuid');
const mailService = require('../service/mail-service');
const tokenService = require('../service/token-service');
const ApiErrors = require('../exceptions/app-errors');

class UserService {
    async registration(email, password) {

        const candidate = await UserModel.findOne({email});

        if(candidate) {
            throw ApiErrors.BadRequest(`Пользоватьль с адресом ${email} уже существует `)
        }

        const hushPassword = await bcrypt.hash(password, 3);
        const activationLink = uuid.v4();
        const user = await UserModel.create({email, password: hushPassword, activationLink})
        // await mailService.sendActivationMail(email, `${process.env.API_URL}/api/activate/${activationLink}`);

        const userDto =  new UserDto(user);
        const tokens = tokenService.generateTokens({...userDto});
        await tokenService.saveToken(userDto.id, tokens.refreshToken);

        return {
            ...tokens,
            user: userDto
        }

    }

    async login(email, password) {
        const user = await UserModel.findOne({email});
        if(!user) {
            throw ApiErrors.BadRequest('User not Found')
        }
        const isPassEquals = await bcrypt.compare(password, user.password);

        if(!isPassEquals){
            throw ApiErrors.BadRequest('Неверный пароль или email')
        }

        const userDto = new UserDto(user);
        const tokens = tokenService.generateTokens({...userDto});

        await tokenService.saveToken(userDto.id, tokens.refreshToken);

        return {
            ...tokens,
            user: userDto
        }
    }

    async logout(refreshToken) {
        const token = await tokenService.removeToken(refreshToken)
        return token;
    }

    async refresh(refreshToken) {
        if(!refreshToken){
            throw ApiErrors.UnauthorizedError();
        }

        const userData = tokenService.validateRefreshToken(refreshToken);
        const tokenFromDb = await tokenService.findToken(refreshToken);
        if(!tokenFromDb || !userData) {
            throw ApiErrors.UnauthorizedError();
        }

        const user = await UserModel.findById(userData.id)
        const userDto = new UserDto(user);
        const tokens = tokenService.generateTokens({...userDto});

        await tokenService.saveToken(userDto.id, tokens.refreshToken);

        return {
            ...tokens,
            user: userDto
        }

    }

    async getAllUsers() {
        const users = await UserModel.find();
        return users
    }

}

module.exports = new UserService();
