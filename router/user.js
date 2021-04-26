const express = require('express')
const {
    users_get_all,
    users_signup_user,
    users_login_user
} = require('../controller/user')
const router = express.Router()

// userInfo
router.get("/", users_get_all)

// 회원가입
router.post("/signup", users_signup_user)

// 로그인
router.post('/login', users_login_user)

module.exports = router