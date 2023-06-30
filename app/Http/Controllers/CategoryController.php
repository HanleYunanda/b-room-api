<?php

namespace App\Http\Controllers;

use App\Models\Category;
use Illuminate\Http\Request;
use App\Http\Resources\CategoryResource;
use Illuminate\Support\Facades\Validator;

class CategoryController extends Controller
{
    /**
     * Display a listing of the resource.
     */
    public function index()
    {
        $categories = Category::all();
        return (new ApiRule)->responsemessage(
            "Categories data",
            CategoryResource::collection($categories),
            200
        );
    }

    /**
     * Store a newly created resource in storage.
     */
    public function store(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string'
        ]);

        if($validator->fails()) {
            return (new ApiRule)->responsemessage(
                "There was an error in the data you inputted",
                $validator->errors(),
                422
            );
        } else {
            if($category = Category::create($validator->validated())) {
                return (new ApiRule)->responsemessage(
                    "New category created successfully",
                    new CategoryResource($category),
                    200
                );
            } else {
                return (new ApiRule)->responsemessage(
                    "Failed to create category",
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
        $category = Category::find($id);

        if(!$category) {
            return (new ApiRule)->responsemessage(
                "Category not found",
                null,
                404
            );
        } else {
            return (new ApiRule)->responsemessage(
                "Category data",
                new CategoryResource($category),
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
            'name' => 'required|string'
        ]);

        $category = Category::find($id);
        if(!$category) {
            return (new ApiRule)->responsemessage(
                "Category data not found",
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
            if($category->update($validator->validated())) {
                return (new ApiRule)->responsemessage(
                    "Category data updated",
                    new CategoryResource($category),
                    200
                );
            } else {
                return (new ApiRule)->responsemessage(
                    "Failed to update category data",
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
        $category = Category::find($id);

        if (!$category){
            return (new ApiRule)->responsemessage(
                "Category data not found",
                null,
                404
            );
        }

        if ($category -> delete()){
            return (new ApiRule)->responsemessage(
                "Category data deleted",
                new CategoryResource($category),
                200
            );
        } else {
            return (new ApiRule)->responsemessage(
                "Failed to delete category data",
                null,
                500
            );
        }
    }
}
