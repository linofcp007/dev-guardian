<?php

use App\Http\Controllers\OrderController;
use Illuminate\Support\Facades\Route;

$appEnv = $_ENV['APP_ENV'] ?? 'production';

Route::get('/laravel/orders', [OrderController::class, 'index']);
Route::post('/laravel/orders', [OrderController::class, 'store']);
Route::put('/laravel/orders/{order}', [OrderController::class, 'update']);
Route::delete('/laravel/orders/{order}', [OrderController::class, 'destroy']);

// Not a route: a facade call whose name is not an HTTP verb.
Route::middleware('auth')->group(
	function () use ( $appEnv ) {
		Route::patch( '/laravel/orders/{order}/status', array( OrderController::class, 'status' ) );
	}
);
