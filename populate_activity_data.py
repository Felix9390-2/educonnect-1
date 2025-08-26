#!/usr/bin/env python3
"""
Script to populate sample daily posting activity data for testing.
This will create realistic historical data for the last 30 days.
"""

from app import app, db
from models import User, DailyPostingActivity, Post
from datetime import date, timedelta
import random

def populate_sample_data():
    """Populate sample daily posting activity data"""
    with app.app_context():
        print("Creating sample daily posting activity data...")
        
        # Get all students (non-admin, non-parent users)
        students = User.query.filter_by(is_admin=False, is_parent=False).all()
        
        if not students:
            print("No students found. Please create some student accounts first.")
            return
        
        # Generate data for the last 30 days
        end_date = date.today()
        start_date = end_date - timedelta(days=29)
        
        activity_count = 0
        
        for student in students:
            print(f"Generating activity data for {student.full_name}...")
            
            current_date = start_date
            while current_date <= end_date:
                # Random chance of posting (70% chance of posting on any given day)
                if random.random() < 0.7:
                    # Random number of posts (1-4 posts per day when active)
                    post_count = random.randint(1, 4)
                    
                    # Check if activity record already exists
                    existing_activity = DailyPostingActivity.query.filter_by(
                        user_id=student.id,
                        date=current_date
                    ).first()
                    
                    if not existing_activity:
                        activity = DailyPostingActivity(
                            user_id=student.id,
                            date=current_date,
                            post_count=post_count
                        )
                        db.session.add(activity)
                        activity_count += 1
                
                current_date += timedelta(days=1)
        
        # Commit all changes
        db.session.commit()
        
        print(f"✅ Successfully created {activity_count} daily activity records!")
        print("The parent dashboard chart will now show real data.")

if __name__ == '__main__':
    populate_sample_data()