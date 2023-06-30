<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use App\Http\Resources\UserResource;
use Illuminate\Http\Resources\Json\JsonResource;

class ReservationResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request): array
    {
        return [
            'id' => $this->id,
            'user_id' => $this->user_id,
            'room_id' => $this->room_id,
            'description' => $this->description,
            'check_in' => $this->check_in,
            'check_out' => $this->check_out,
            'user' => new UserResource($this->user),
            'room' => new RoomResource($this->room),
            'tools' => $this->tool
        ];
    }
}
