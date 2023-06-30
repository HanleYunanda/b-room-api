<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth:sanctum', [
            'except' => 'login'
        ]);
    }

    public function login(Request $request) {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        $user = User::where('email', $request->email)->first();

        if (! $user || ! Hash::check($request->password, $user->password)) {
            return (new ApiRule)->responsemessage(
                "Failed to login",
                null,
                400
            );
        }

        if ($user->role == 'ADMIN') {
            $token = $user->createToken($user->name, ['admin-access'])->plainTextToken;
        } else {
            $token = $user->createToken($user->name, ['user-access'])->plainTextToken;
        }

        $data = [
            'user' => $user,
            'token' => $token,
        ];
        return (new ApiRule)->responsemessage(
            "Successfully logged in",
            $data,
            200
        );
        // return $user->createToken($request->device_name)->plainTextToken;
    }

    public function me(Request $request) {
        return (new ApiRule)->responsemessage(
            "Logged in user's data",
            Auth::user(),
            200
        );
    }

    public function logout(Request $request) {
        if ($request->user()->currentAccessToken()->delete()) {
            return (new ApiRule)->responsemessage(
                "Successfully logged out",
                null,
                200
            );
        } else {
            return (new ApiRule)->responsemessage(
                "Failed to log out",
                null,
                400
            );
        }
    }
}
