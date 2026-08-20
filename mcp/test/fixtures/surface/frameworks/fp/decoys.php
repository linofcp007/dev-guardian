<?php
// F40 a non-Laravel class also called Route
Route::get('not/a/leading/slash', 'x');
// F41 a Collection-ish facade
Cache::get('/cached/thing');
