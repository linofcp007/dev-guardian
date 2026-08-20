<?php

use App\Http\Controllers\OrderController;
use Illuminate\Support\Facades\Route;
use App\Models\{Order, Invoice};
use App\Support\Helper as H;
use function App\Support\slugify;

// H01 control
Route::get('/orders', [OrderController::class, 'index']);

// H02 fluent middleware chain — dominant modern Laravel form
Route::middleware(['auth:sanctum'])->get('/orders/secure', [OrderController::class, 'secure']);

// H03 prefix group; inner Route:: calls still direct
Route::prefix('admin')->group(function () {
    Route::get('/dashboard', [OrderController::class, 'dash']);
});

// H04 resource routes — one call, many routes
Route::resource('photos', OrderController::class);
Route::apiResource('books', OrderController::class);

// H05 name chain AFTER the verb (verb call is still first)
Route::post('/orders', [OrderController::class, 'store'])->name('orders.store');

// H06 Route::match
Route::match(['get', 'post'], '/either', [OrderController::class, 'either']);

// H07 env
$e1 = getenv('APP_ENV');
$e2 = $_ENV['APP_KEY'];
$e3 = $_SERVER['HTTP_HOST'];
$e4 = env('LARAVEL_ENV');
