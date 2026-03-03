<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller {

    // User Registration
    public function register(Request $request) {
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

        return $this->createTokenResponse($user);
    }

    // Login
    public function login(Request $request) {
        $credentials = $request->only('email', 'password');

        if (!$user = Auth::attempt($credentials)) {
            return response()->json(['error' => 'Неверные данные'], 401);
        }

        $user = Auth::user();
        return $this->createTokenResponse($user);
    }

    // Logout
    public function logout() {
        Auth::logout();

        return response()->json(['message' => 'Выход выполнен успешно'])
                         ->withCookie(cookie()->forget('access_token'))
                         ->withCookie(cookie()->forget('refresh_token'));
    }

    // Get Authenticated User
    public function me() {
        return response()->json(Auth::user());
    }

    // Refresh access token using refresh cookie
    public function refresh(Request $request) {
        $refreshToken = $request->cookie('refresh_token');
        if (!$refreshToken) {
            return response()->json(['error' => 'Нет refresh токена'], 401);
        }

        try {
            $user = JWTAuth::setToken($refreshToken)->toUser();
        } catch (\Exception $e) {
            return response()->json(['error' => 'Недействительный refresh токен'], 401);
        }

        return $this->createTokenResponse($user);
    }

    // Helper: create access & refresh cookies
    protected function createTokenResponse($user) {
        $accessToken = JWTAuth::fromUser($user, ['exp' => now()->addMinutes(30)->timestamp]);
        $refreshToken = JWTAuth::fromUser($user, ['exp' => now()->addDays(7)->timestamp]);

        $accessCookie = cookie('access_token', $accessToken, 30, '/', null, true, true, false, 'Strict');
        $refreshCookie = cookie('refresh_token', $refreshToken, 60*24*7, '/', null, true, true, false, 'Strict');

        return response()->json(['message' => 'Успешно'])
                        ->withCookie($accessCookie)
                        ->withCookie($refreshCookie);
    }
}
