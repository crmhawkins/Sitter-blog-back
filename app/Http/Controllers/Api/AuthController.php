<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

use App\Models\User;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:api', ['except' => ['login']]);
        $this->middleware('setDefaultGuard');
    }

    public function login(Request $request)
{
    $request->validate([
        'email' => 'required|string|email',
        'password' => 'required|string',
    ]);

    $credentials = $request->only('email', 'password');
    $user = User::where('email', $credentials['email'])->first();

    // Verificar si el usuario existe y la contraseña es correcta
    if (!$user || !Hash::check($credentials['password'], $user->password) || !$user->is_admin) {
        return response()->json([
            'message' => 'Unauthorized',
        ], 401);
    }

    // Si el usuario ya tiene un token en la base de datos, lo devuelve sin regenerarlo
    if ($user->api_token) {
        return response()->json([
            'user' => $user,
            'authorization' => [
                'token' => $user->api_token,
                'type' => 'bearer',
            ]
        ]);
    }

    // Si no tiene un token, generamos uno y lo guardamos en la BD
    $token = auth()->login($user);
    $user->api_token = $token; // Guardamos el token en la base de datos
    $user->save();

    return response()->json([
        'user' => $user,
        'authorization' => [
            'token' => $token,
            'type' => 'bearer',
        ]
    ]);
}



    public function logout()
    {
        Auth::logout();
        return response()->json([
            'message' => 'Successfully logged out',
        ]);
    }

    public function refresh()
    {
        return response()->json([
            'user' => Auth::user(),
            'authorisation' => [
                'token' => Auth::refresh(),
                'type' => 'bearer',
            ]
        ]);
    }
}
