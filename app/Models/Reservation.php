<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Reservation extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id',
        'room_id',
        'description',
        'check_in',
        'check_out',
    ];

    public function user() : BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function room() : BelongsTo
    {
        return $this->belongsTo(Room::class);
    }

    public function tool() : HasMany
    {
        return $this->hasMany(Tool::class);
    }
}
