<?php

namespace App\Http\Controllers;

use App\Http\Resources\UserResource;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;

class UserController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $users = User::all();
        return (new ApiRule)->responsemessage(
            "Users data",
            UserResource::collection($users),
            200
        );
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|string',
            'role' => 'required|in:STUDENT,LECTURER'
        ]);

        if($validator->fails()) {
            return (new ApiRule)->responsemessage(
                "There was an error in the data you inputted",
                $validator->errors(),
                422
            );
        } else {
            $validatedData = $validator->validated();
            $validatedData['password'] = bcrypt($validatedData['password']);
            $user = User::create($validatedData);
            if ($user) {
                return (new ApiRule)->responsemessage(
                    "New user created successfully",
                    new UserResource($user),
                    200
                );
            } else {
                return (new ApiRule)->responsemessage(
                    "Failed to create user",
                    null,
                    500
                );
            }
        }
    }

    /**
     * Display the specified resource.
     */
    public function show($id)
    {
        $user = User::find($id);

        if(!$user) {
            return (new ApiRule)->responsemessage(
                "User not found",
                null,
                404
            );
        } else {
            return (new ApiRule)->responsemessage(
                "User data",
                new UserResource($user),
                200
            );
        }
    }

    /**
     * Update the specified resource in storage.
     */
    public function update(Request $request, $id)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string',
            'email' => 'required|email',
            'password' => 'required|string',
            'role' => 'required|in:STUDENT,LECTURER'
        ]);

        $user = User::find($id);
        if(!$user) {
            return (new ApiRule)->responsemessage(
                "User data not found",
                null,
                404
            );
        }

        if($validator->fails()) {
            return (new ApiRule)->responsemessage(
                "There was an error in the data you inputted",
                $validator->errors(),
                422
            );
        } else {
            if($user->update($validator->validated())) {
                return (new ApiRule)->responsemessage(
                    "User data updated",
                    new UserResource($user),
                    200
                );
            } else {
                return (new ApiRule)->responsemessage(
                    "Failed to update user data",
                    null,
                    500
                );
            }
        }
    }

    /**
     * Remove the specified resource from storage.
     */
    public function destroy($id)
    {
        $user = User::find($id);

        if (!$user){
            return (new ApiRule)->responsemessage(
                "User data not found",
                null,
                404
            );
        }

        if ($user -> delete()){
            return (new ApiRule)->responsemessage(
                "User data deleted",
                new UserResource($user),
                200
            );
        } else {
            return (new ApiRule)->responsemessage(
                "Failed to delete user data",
                null,
                500
            );
        }
    }
}
