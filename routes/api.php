<?php

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Middleware\JwtCookieAuth;

Route::get('/user', function (Request $request) {
    return $request->user();
})->middleware('auth:sanctum');



 Route::post('register', [AuthController::class, 'register']);

 Route::post('login', [AuthController::class, 'login']);

 // Protected routes (require JWT token)

 Route::middleware([JwtCookieAuth::class])->group(function () {
     Route::get('me', [AuthController::class, 'me']);
     });
     
     Route::post('logout', [AuthController::class, 'logout']);

Route::post('refresh', [AuthController::class, 'refresh'])->middleware('auth:api');



