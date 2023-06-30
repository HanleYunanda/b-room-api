<?php

namespace App\Http\Resources;

use Illuminate\Http\Request;
use App\Http\Resources\ReservationResource;
use Illuminate\Http\Resources\Json\JsonResource;

class ToolResource extends JsonResource
{
    /**
     * Transform the resource into an array.
     *
     * @return array<string, mixed>
     */
    public function toArray(Request $request)
    {
        return [
            'id' => $this->id,
            'name' => $this->name,
            'type' => $this->type,
            'reservation_id' => $this->reservation_id,
            'reservation' => $this->reservation
        ];
    }
}
