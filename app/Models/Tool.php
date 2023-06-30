<?php

namespace App\Models;

use App\Models\Reservation;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class Tool extends Model
{
    use HasFactory;

    protected $fillable = [
        'name',
        'type',
        'reservation_id',
    ];

    public function reservation() : BelongsTo
    {
        return $this->belongsTo(Reservation::class);
    }
}
