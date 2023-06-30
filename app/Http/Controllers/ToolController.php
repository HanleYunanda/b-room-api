<?php

namespace App\Http\Controllers;

use App\Models\Tool;
use Illuminate\Http\Request;
use App\Http\Resources\ToolResource;
use Illuminate\Support\Facades\Validator;

class ToolController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $tools = Tool::all();
        return (new ApiRule)->responsemessage(
            "Tools data",
            ToolResource::collection($tools),
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
            'type' => 'required',
            'reservation_id' => 'required|integer|exists:reservations,id',
        ]);

        if($validator->fails()) {
            return (new ApiRule)->responsemessage(
                "There was an error in the data you inputted",
                $validator->errors(),
                422
            );
        } else {
            if($tool = Tool::create($validator->validated())) {
                return (new ApiRule)->responsemessage(
                    "New tool created successfully",
                    new ToolResource($tool),
                    200
                );
            } else {
                return (new ApiRule)->responsemessage(
                    "Failed to create tool",
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
        $tool = Tool::find($id);

        if(!$tool) {
            return (new ApiRule)->responsemessage(
                "Tool not found",
                null,
                404
            );
        } else {
            return (new ApiRule)->responsemessage(
                "Tool data",
                new ToolResource($tool),
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
            'type' => 'required',
            'reservation_id' => 'required|integer|exists:reservations,id',
        ]);

        $tool = Tool::find($id);
        if(!$tool) {
            return (new ApiRule)->responsemessage(
                "Tool data not found",
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
            if($tool->update($validator->validated())) {
                return (new ApiRule)->responsemessage(
                    "Tool data updated",
                    new ToolResource($tool),
                    200
                );
            } else {
                return (new ApiRule)->responsemessage(
                    "Failed to update tool data",
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
        $tool = Tool::find($id);

        if (!$tool){
            return (new ApiRule)->responsemessage(
                "Tool data not found",
                null,
                404
            );
        }

        if ($tool -> delete()){
            return (new ApiRule)->responsemessage(
                "Tool data deleted",
                new ToolResource($tool),
                200
            );
        } else {
            return (new ApiRule)->responsemessage(
                "Failed to delete tool data",
                null,
                500
            );
        }
    }
}
