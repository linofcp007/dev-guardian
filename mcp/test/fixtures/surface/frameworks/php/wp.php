<?php
namespace Guardian\Rest;

// W01 control — literal namespace
add_action('rest_api_init', function () {
    register_rest_route('guardian/v1', '/things', [
        'methods'  => 'GET',
        'callback' => '__return_empty_array',
        'permission_callback' => '__return_true',
    ]);
});

// W02 class-constant namespace + array of endpoint descriptors
class Controller {
    public function register() {
        register_rest_route(self::NS, '/items/(?P<id>\d+)', array(
            array('methods' => 'GET', 'callback' => array($this, 'get')),
        ));
    }
}

// W03 admin-ajax and rewrite endpoints (not REST, must not match)
add_action('wp_ajax_my_action', 'my_handler');
