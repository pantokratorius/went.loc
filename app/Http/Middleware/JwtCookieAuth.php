<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\Auth;
use Tymon\JWTAuth\Facades\JWTAuth;
use Tymon\JWTAuth\Exceptions\JWTException;

class JwtCookieAuth
{
    public function handle($request, Closure $next)
    {
        // Get the token from the cookie
        $token = $request->cookie('access_token');

        if (!$token) {
            return response()->json([
                'message' => 'Unauthenticated – no token'
            ], 401);
        }

        try {
            // Authenticate the user from the cookie token
            $user = JWTAuth::setToken($token)->authenticate();

            if (!$user) {
                return response()->json(['message' => 'Unauthenticated – invalid token'], 401);
            }

            // Log the user into Laravel's Auth system
            Auth::login($user);

        } catch (JWTException $e) {
            return response()->json([
                'message' => 'Unauthenticated – token error',
                'error' => $e->getMessage()
            ], 401);
        }

        return $next($request);
    }
}