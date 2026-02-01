<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Storage;

class AuthController extends Controller
{
    // REGISTER
    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:6',
            'image' => 'required|image|mimes:jpg,jpeg,png|max:2048',
        ]);

        $imagePath = $request->file('image')->store('profiles', 'public');

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'image' => $imagePath,
        ]);


        return response()->json([
            'user' => $user
        ], 201);
    }

    // LOGIN
    public function login(Request $request)
{
    $credentials = $request->validate([
        'email' => 'required|email',
        'password' => 'required',
    ]);

    $user = User::where('email', $credentials['email'])->first();

    if (!$user || !Hash::check($credentials['password'], $user->password)) {
        return response()->json(['message' => 'Invalid credentials'], 401);
    }

    // create a token for API access
    $token = $user->createToken('api-token', [], now()->addDays(7))->plainTextToken;


    return response()->json([
        'user' => $user,
        'token' => $token
    ]);
}


    // LOGOUT
    public function logout(Request $request)
{
    $request->user()->currentAccessToken()->delete();

    return response()->json([
        'message' => 'Logged out'
    ]);
}


    // PROFILE (Protected)
    public function profile(Request $request)
    {
        return response()->json($request->user());
    }
}
