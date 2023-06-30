<?php

namespace App\Http\Controllers;

use App\Models\Room;
use Illuminate\Http\Request;
use App\Http\Resources\RoomResource;
use Illuminate\Support\Facades\Validator;

class RoomController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $rooms = Room::all();

        return (new ApiRule)->responsemessage(
            "Room data",
            RoomResource::collection($rooms),
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
            'category_id' => 'required|integer|exists:categories,id',
            'capacity' => 'required|integer'
        ]);

        if($validator->fails()) {
            return (new ApiRule)->responsemessage(
                "There was an error in the data you inputted",
                $validator->errors(),
                422
            );
        } else {
            if($room = Room::create($validator->validated())) {
                return (new ApiRule)->responsemessage(
                    "New room created successfully",
                    new RoomResource($room),
                    200
                );
            } else {
                return (new ApiRule)->responsemessage(
                    "Failed to create room",
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
        $room = Room::find($id);

        if(!$room) {
            return (new ApiRule)->responsemessage(
                "Room not found",
                null,
                404
            );
        } else {
            return (new ApiRule)->responsemessage(
                "Room data",
                new RoomResource($room),
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
            'category_id' => 'required|exists:categories,id',
            'capacity' => 'required|integer'
        ]);

        $room = Room::find($id);
        if(!$room) {
            return (new ApiRule)->responsemessage(
                "Room data not found",
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
            if($room->update($validator->validated())) {
                return (new ApiRule)->responsemessage(
                    "Room data updated",
                    new RoomResource($room),
                    200
                );
            } else {
                return (new ApiRule)->responsemessage(
                    "Failed to update room data",
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
        $room = Room::find($id);

        if (!$room){
            return (new ApiRule)->responsemessage(
                "Room data not found",
                null,
                404
            );
        }

        if ($room -> delete()){
            return (new ApiRule)->responsemessage(
                "Room data deleted",
                new RoomResource($room),
                200
            );
        } else {
            return (new ApiRule)->responsemessage(
                "Failed to delete room data",
                null,
                500
            );
        }
    }
}
