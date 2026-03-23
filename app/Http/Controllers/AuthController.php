<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    // ✅ REGISTER
    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|string|min:6|confirmed',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        return $this->sendToken($user);
    }

    // ✅ LOGIN
    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');

        if (!$user = Auth::attempt($credentials)) {
            return response()->json(['error' => 'Неверные данные'], 401);
        }

        $user = Auth::user();
        return $this->sendToken($user);
    }

    // ✅ LOGOUT

public function logout()
{
    try {
        $token = JWTAuth::parseToken()->getToken();
        JWTAuth::invalidate($token); // blacklists the token
    } catch (\Exception $e) {
        // token missing or invalid
    }

    // Delete cookie
    $secure = config('app.env') === 'production';
    $accessCookie = cookie('access_token', '', -1, '/', null, $secure, true, false, 'Strict');

    return response()->json(['message' => 'Выход выполнен успешно'])
                    ->withCookie($accessCookie);
}

    // ✅ CURRENT USER
    public function me()
    {
        return response()->json(Auth::user());
    }

    // ✅ HELPER: SEND ACCESS TOKEN COOKIE
    protected function sendToken($user)
    {
        $secure = config('app.env') === 'production';

        // Generate token normally; TTL is handled by config/jwt.php
        $accessToken = JWTAuth::fromUser($user);

        // Cookie lifetime: 1 week = 10080 minutes
        $accessCookie = cookie(
            'access_token',
            $accessToken,
            60 * 24 * 7,
            '/',
            null,
            $secure,
            true, // httpOnly
            false,
            'Strict'
        );

        return response()->json(['message' => 'Успешно'])
                        ->withCookie($accessCookie);
    }
}