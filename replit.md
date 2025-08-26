# Overview

This is a Flask-based school social media platform that allows students to create posts, interact with each other, and provides administrative oversight. The platform features role-based access control with separate interfaces for students and administrators, user authentication, post creation and management, social feed system with likes and comments functionality, comprehensive groups system with public/private groups, group chat functionality, and improved direct messaging interface.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Backend Architecture
- **Framework**: Flask web framework with SQLAlchemy ORM for database operations
- **Database**: SQLite for development with configurable database URI support for production deployments
- **Session Management**: Flask's built-in session handling with configurable secret keys
- **Password Security**: Werkzeug's password hashing utilities for secure authentication

## Database Design
- **User Model**: Supports both students and administrators with role-based permissions (admin, prefect flags)
- **Post Model**: Text-based posts with timestamps and author relationships
- **Comment Model**: Threaded discussions on posts (referenced but not fully implemented)
- **Like Model**: User engagement tracking (referenced but not fully implemented)
- **Group Model**: Public and private groups with unique invite codes for private groups
- **GroupMembership Model**: Many-to-many relationship between users and groups with admin controls
- **GroupMessage Model**: Real-time group chat functionality within groups
- **DirectMessage Model**: Private messaging between students
- **Classwork Model**: Teacher PDF uploads with file management and browser viewing capabilities
- **Homework Model**: Assignment creation with due dates, descriptions, and optional attachments
- **Circular Model**: School announcements with categories, priorities, expiry dates, and file attachments
- **Relationships**: Proper foreign key constraints with cascade delete operations

## Authentication & Authorization
- **Session-based Authentication**: User sessions stored server-side with role information
- **Role-based Access Control**: Separate dashboards and permissions for students vs administrators
- **Default Admin Account**: Automatically created admin user for initial system access

## Frontend Architecture
- **Template Engine**: Jinja2 templating with Bootstrap 5 for responsive design
- **UI Framework**: Bootstrap 5 with Font Awesome icons for consistent styling
- **Custom Styling**: CSS variables for theme consistency with school-appropriate color scheme
- **Responsive Design**: Mobile-friendly interface with collapsible navigation

## Application Structure
- **MVC Pattern**: Clear separation with models, routes (controllers), and templates (views)
- **Blueprints**: Potential for modular organization (though currently in single files)
- **Error Handling**: Flash message system for user feedback
- **Development Features**: Debug logging and development server configuration

# External Dependencies

## Frontend Libraries
- **Bootstrap 5.3.0**: CSS framework for responsive design and UI components
- **Font Awesome 6.0.0**: Icon library for user interface elements

## Python Packages
- **Flask**: Core web framework
- **Flask-SQLAlchemy**: Database ORM and management
- **Werkzeug**: Password hashing and WSGI utilities

## Infrastructure
- **SQLite**: Default database (configurable for other databases via DATABASE_URL)
- **ProxyFix Middleware**: Support for reverse proxy deployments
- **Environment Variables**: Configuration through SESSION_SECRET and DATABASE_URL

# Recent Changes (August 2025)

## Parent Account System Implementation (August 19, 2025)
- **Comprehensive Parent Monitoring System**: Added full parent account functionality with is_parent field and ParentChild relationship model
- **View-Only Social Feed**: Parents can view the complete school social feed but cannot create posts or comments (read-only access)
- **Interactive Activity Analytics**: Added Chart.js-powered daily posting activity graph showing children's posting patterns over the last 30 days
- **Enhanced Communication Panel**: Three-tab monitoring interface for Children's Messages, Group Activity, and Academic Updates with detailed oversight capabilities
- **Messaging Restrictions**: Parents cannot send or receive direct messages - complete messaging system lockout for monitoring-only access
- **Parent Dashboard**: Comprehensive monitoring interface showing all posts, children's activities, homework assignments, and engagement statistics
- **Role-Based Navigation**: Updated login flow and navigation to handle parent accounts with appropriate redirects and access controls

## Parent Account Features
- **Social Feed Monitoring**: View-only access to all school posts with "Your Child" badges for easy identification
- **Activity Analytics**: Interactive graphs and statistics showing children's posting frequency, message counts, and group participation
- **Communication Monitoring**: Three-panel interface for monitoring children's messages, group activities, and academic progress
- **Messaging Restrictions**: Complete prevention of messaging to/from parent accounts with clear error messages and redirects
- **Account Creation**: Admin interface allows creating parent accounts and assigning children for monitoring purposes

## Circular System Implementation (August 18, 2025)
- **School Circulars Feature**: Added comprehensive circular/announcement system for official school communications
- **Role-based Creation**: Teachers and admins can create circulars with categories (Holiday, Event, Reminder, General, Academic, Sports, Emergency)
- **Priority System**: High, Normal, and Low priority circulars with visual indicators and badges
- **Expiry Management**: Optional expiry dates for time-sensitive announcements with automatic filtering
- **File Attachments**: Support for file attachments on circulars with secure upload handling
- **Universal Access**: All users can view circulars, teachers/admins can create and manage them
- **Management Interface**: Separate tabs for viewing all circulars vs. personal created circulars with delete functionality

## Enhanced Teacher & Student Account System (August 19, 2025)
- **Class Teacher System**: Added class_teacher_grade and class_teacher_section fields for teachers to designate class teachers
- **Section Management**: Added section field (A-I) for both students and teachers for better organization
- **Password Confirmation**: Added confirm password requirement with client-side and server-side validation
- **Auto Bio Updates**: Students' bios automatically include their class teacher when grades and sections match
- **Enhanced Admin Interface**: Updated account creation and edit forms to handle new teacher and student fields
- **Professional Teacher Tags**: Teachers marked as class teachers display with enhanced role indicators

## Teacher Account System Implementation (August 18, 2025)
- **Teacher Account Support**: Added full teacher account functionality with is_teacher and subject_taught fields in User model
- **Teacher Creation Interface**: Updated admin account creation form with dynamic teacher/student field switching
- **Teacher Moderation Powers**: Teachers can now delete posts and comments like prefects and admins through enhanced permission system
- **Teacher Role Display**: Professional teacher badges and subject information display throughout the application
- **Template Error Resolution**: Fixed multiple template rendering issues including like_count() property calls and admin accounts data structure
- **Session Management**: Resolved authentication session persistence issues that were causing login redirects

## Teacher Account Features
- **Subject Specialization**: Teachers have subject_taught field to specify their teaching subject
- **Moderation Capabilities**: Full post and comment deletion rights equivalent to prefects and administrators
- **Professional Display**: Clean teacher role badges distinguishing them from students and prefects
- **Admin Management**: Admins can create, edit, and manage teacher accounts through the enhanced account management interface

## Hierarchical Powers System Implementation (August 15, 2025)
- **Admin Powers**: Admins can now delete any group and access a comprehensive Communications Panel to monitor all direct messages and group messages
- **Prefect Powers**: Prefects can delete posts and comments from any user for moderation purposes
- **Admin Communications Panel**: New dedicated interface for monitoring all platform communications with tabbed view for DMs, group messages, and group management
- **Enhanced Moderation UI**: Added delete buttons for posts and comments with clear role-based permissions (own content, prefect moderation, admin override)
- **Group Management**: Admins can delete any group from both the groups page and communications panel, while group creators retain control over their own groups

## House System & Role Tags Implementation (August 15, 2025)
- **House System Added**: Implemented four school houses for prefects: St. Patrick (Green), St. Raphael (Yellow), St. Nicolas (Orange), and St. Michael (Blue)
- **Professional Role Tags**: Added clean, professional role badges throughout the application showing admin status, prefect houses, and student roles
- **Enhanced Account Creation**: Moved account creation to manage accounts page with house selection and improved role management
- **Clear Role Hierarchy**: Professional visual distinction between admin (red), house prefects (house colors), regular prefects (yellow), and students (secondary)

## Enhanced Admin Functionality (August 14, 2025)
- **Unified User Experience**: Admin users now have access to all student social features including posts, groups, messaging, and lost & found
- **Account Management System**: New comprehensive admin interface for managing all user accounts with detailed statistics and editing capabilities
- **Enhanced Lost & Found**: Direct "mark as found" functionality from admin dashboard with location and date tracking
- **Cross-Platform Messaging**: Admin can now message any user (students and other admins), students can message admin
- **Social Admin Integration**: Admin can create posts, join/create groups, participate in discussions like regular users while retaining administrative privileges

## Account Management Features
- **User Statistics Dashboard**: View post counts, message activity, and group memberships for all users
- **Advanced User Editing**: Edit user profiles, grades, prefect status, passwords, and bio information
- **Safe Account Deletion**: Delete student accounts with confirmation dialogs and activity preservation warnings
- **Role Management**: Clear distinction between admin and student roles with appropriate access controls

## Groups System Implementation
- **Public Groups**: Open for all students to join directly from groups page
- **Private Groups**: Require unique 8-character invite codes for access
- **Group Administration**: Group creators become admins with delete and invite management permissions
- **Group Chat**: Real-time messaging system within groups with scrollable chat interface
- **Navigation**: Easy access to group chat through prominent "Chat & Members" buttons

## Enhanced Messaging System
- **Direct Messages**: Improved interface showing all students in card format for easy conversation access
- **User-Friendly Design**: Replaced email-style interface with direct student directory approach
- **Conversation Status**: Clear indicators for existing conversations and unread message counts
- **Quick Access**: Direct "Start Chat" and "Continue Chat" buttons for each student

## UI/UX Improvements
- **Group Navigation**: Back buttons and quick navigation between chat and members sections
- **Auto-scroll**: Chat containers automatically scroll to latest messages
- **Visual Indicators**: Clear badges for group admins, prefects, and unread message counts
- **Responsive Design**: Card-based layouts optimized for desktop and mobile viewing