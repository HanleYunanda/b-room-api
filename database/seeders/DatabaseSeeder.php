<?php

namespace Database\Seeders;

// use Illuminate\Database\Console\Seeds\WithoutModelEvents;

use App\Models\Category;
use App\Models\Reservation;
use App\Models\Room;
use App\Models\Tool;
use App\Models\User;
use Illuminate\Database\Seeder;
use Illuminate\Database\Eloquent\Model;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        // \App\Models\User::factory(10)->create();

        // \App\Models\User::factory()->create([
        //     'name' => 'Test User',
        //     'email' => 'test@example.com',
        // ]);

        User::create([
            'name' => 'Hanley',
            'email' => 'hanley.saputra@binus.ac.id',
            'password' => bcrypt('12345'),
            'role' => 'Student'
        ]);

        User::create([
            'name' => 'Gavra',
            'email' => 'gavratsany@gmail.com',
            'password' => bcrypt('12345'),
            'role' => 'Student'
        ]);

        Category::create([
            'name' => 'Regular Class',
        ]);

        Category::create([
            'name' => 'Creative Class',
        ]);

        Category::create([
            'name' => 'Smart Class',
        ]);

        Room::create([
            'name' => '0205',
            'category_id' => 2,
            'capacity' => 40
        ]);

        Room::create([
            'name' => '0403',
            'category_id' => 3,
            'capacity' => 40
        ]);

        Reservation::create([
            'user_id' => 1,
            'room_id' => 2,
            'description' => 'Rapat HIMTI',
            'check_in' => '2023-06-09 09:00:00',
            'check_out' => '2023-06-09 11:00:00'
        ]);

        Tool::create([
            'name' => 'Saramonic',
            'type' => 'Microphone',
            'reservation_id' => 1
        ]);
    }
}
