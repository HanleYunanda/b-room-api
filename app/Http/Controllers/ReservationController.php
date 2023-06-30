<?php

namespace App\Http\Controllers;

use App\Models\Reservation;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use App\Http\Resources\ReservationResource;

class ReservationController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $reservations = Reservation::all();

        return (new ApiRule)->responsemessage(
            "Reservation data",
            ReservationResource::collection($reservations),
            200
        );
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'user_id' => 'required|integer|exists:users,id',
            'room_id' => 'required|integer|exists:rooms,id',
            'description' => 'required',
            'check_in' => 'required|date_format:Y-m-d H:i:s',
            'check_out' => 'required|date_format:Y-m-d H:i:s',
        ]);

        if($validator->fails()) {
            return (new ApiRule)->responsemessage(
                "There was an error in the data you inputted",
                $validator->errors(),
                422
            );
        } else {
            if($reservation = Reservation::create($validator->validated())) {
                return (new ApiRule)->responsemessage(
                    "New reservation created successfully",
                    new ReservationResource($reservation),
                    200
                );
            } else {
                return (new ApiRule)->responsemessage(
                    "Failed to create reservation",
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
        $reservation = Reservation::find($id);

        if(!$reservation) {
            return (new ApiRule)->responsemessage(
                "Reservation not found",
                null,
                404
            );
        } else {
            return (new ApiRule)->responsemessage(
                "Reservation data",
                new ReservationResource($reservation),
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
            'user_id' => 'required|integer|exists:users,id',
            'room_id' => 'required|integer|exists:rooms,id',
            'description' => 'required',
            'check_in' => 'required|date_format:Y-m-d H:i:s',
            'check_out' => 'required|date_format:Y-m-d H:i:s',
        ]);

        $reservation = Reservation::find($id);
        if(!$reservation) {
            return (new ApiRule)->responsemessage(
                "Reservation data not found",
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
            if($reservation->update($validator->validated())) {
                return (new ApiRule)->responsemessage(
                    "Reservation data updated",
                    new ReservationResource($reservation),
                    200
                );
            } else {
                return (new ApiRule)->responsemessage(
                    "Failed to update reservation data",
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
        $reservation = Reservation::find($id);

        if (!$reservation){
            return (new ApiRule)->responsemessage(
                "Reservation data not found",
                null,
                404
            );
        }

        if ($reservation -> delete()){
            return (new ApiRule)->responsemessage(
                "Reservation data deleted",
                new ReservationResource($reservation),
                200
            );
        } else {
            return (new ApiRule)->responsemessage(
                "Failed to delete reservation data",
                null,
                500
            );
        }
    }
}
