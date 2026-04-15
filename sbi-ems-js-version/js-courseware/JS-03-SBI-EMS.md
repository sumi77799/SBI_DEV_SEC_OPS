# Employee Management System (EMS)
### Project Abstract — Node.js REST API Training Project
**Prepared for:** DevSecOps Training — SBI
**Tech Stack:** Node.js 20 LTS · Express.js 4.x · Sequelize ORM · MySQL · JWT (jsonwebtoken) · express-validator · Swagger (swagger-jsdoc + swagger-ui-express) · dotenv · Winston · Helmet

---

## 1. Project Overview

The **Employee Management System (EMS)** is a RESTful web service built with Node.js and Express.js that manages the core HR domain of an organization. It handles employees, their departments, their job roles, and the projects they are assigned to — through a clean, layered API.

EMS is the backbone Node.js project used across all training modules. The business domain is intentionally straightforward so that trainees can stay focused on the technology being taught at each stage, without getting lost in complex domain rules.

### Why This Project?

- **Universal domain** — everyone understands employees, departments, and projects
- **Relatable data** — names, emails, salaries, hire dates feel real without being sensitive
- **Progressive complexity** — start with basic CRUD, layer in security, validation, and monitoring
- **Multiple entity relationships** — covers One-to-Many, Many-to-One, and Many-to-Many in one project
- **Security hooks** — salary and PII fields provide natural anchors for access control lessons

### Scope

The EMS API covers four core domains:

- **Employee** — the central entity; personal and employment information
- **Department** — organizational grouping of employees
- **Role** — job designation / seniority level within the organization
- **Project** — business initiatives that employees are assigned to

---

## 2. Business Context

Imagine a mid-sized organization that needs to manage its workforce digitally. The HR team needs to onboard new employees, organize them into departments, assign job roles that reflect their seniority, and track which projects each employee is working on at any given time.

Currently, this is done through spreadsheets and manual processes. The EMS API will serve as the backend system that powers an HR portal, replacing these manual processes with a secure, validated, and auditable REST API.

### 2.1 Business Problems Being Solved

| Problem | How EMS Solves It |
|---|---|
| No central employee registry | Single REST API with validated employee records in MySQL |
| No org structure visibility | Departments with assigned employees queryable via API |
| Role confusion in projects | Each employee carries an org Role; projects carry a separate `projectRole` per assignment |
| No project staffing tracker | Many-to-many Employee-Project assignments with dates and roles |
| Security and access gaps | JWT-based authentication with role-based access control middleware |

---

## 3. Entities and Data Model

The EMS domain consists of four entities that map directly to database tables via Sequelize ORM.

### 3.1 Employee

The central entity of the system. Holds all personal and employment information about an individual.

| Field | Type | Constraint | Description |
|---|---|---|---|
| `id` | INTEGER | PK, Auto-increment | Unique system identifier |
| `firstName` | STRING | NOT NULL | Employee's first name (2–50 chars) |
| `lastName` | STRING | NOT NULL | Employee's last name (2–50 chars) |
| `email` | STRING | NOT NULL, Unique | Business email; used as login identity |
| `phone` | STRING | Optional | Contact number in E.164-compatible format |
| `salary` | DECIMAL(10,2) | NOT NULL | Monthly gross salary; PII — access-controlled |
| `hireDate` | DATEONLY | NOT NULL | Date the employee joined the organization |
| `status` | ENUM | NOT NULL | `ACTIVE` \| `INACTIVE` \| `ON_LEAVE` \| `TERMINATED` |
| `departmentId` | INTEGER | FK, NOT NULL | The department this employee belongs to |
| `roleId` | INTEGER | FK, NOT NULL | The job role / designation of this employee |
| `createdAt` | DATE | Auto, Immutable | Timestamp of record creation (audit) |
| `updatedAt` | DATE | Auto | Timestamp of last record update (audit) |

### 3.2 Department

Represents an organizational unit. Deliberately kept simple — no hierarchy or manager relationship.

| Field | Type | Constraint | Description |
|---|---|---|---|
| `id` | INTEGER | PK, Auto-increment | Unique system identifier |
| `name` | STRING | NOT NULL, Unique | Department name (e.g. Engineering, HR, Finance) |
| `description` | STRING | Optional | Short description of the department's function |

### 3.3 Role

Represents a job designation within the organization — not a JWT/auth role. Carries a seniority level to enable sorting and access decisions.

| Field | Type | Constraint | Description |
|---|---|---|---|
| `id` | INTEGER | PK, Auto-increment | Unique system identifier |
| `name` | STRING | NOT NULL, Unique | Designation name (e.g. `SENIOR_ENGINEER`, `HR_MANAGER`) |
| `description` | STRING | Optional | Details about the role's responsibilities |
| `level` | INTEGER | NOT NULL, 1–10 | Seniority level; 1 = Junior, 5 = Lead, 10 = Principal |

### 3.4 Project

Represents a business initiative. Employees are assigned to projects through the `EmployeeProject` join table, which tracks when they were assigned and what role they play on that project.

| Field | Type | Constraint | Description |
|---|---|---|---|
| `id` | INTEGER | PK, Auto-increment | Unique system identifier |
| `name` | STRING | NOT NULL, Unique | Project name (2–150 chars) |
| `description` | TEXT | Optional | Summary of project objectives (up to 500 chars) |
| `startDate` | DATEONLY | NOT NULL | Project kick-off date |
| `endDate` | DATEONLY | Optional | Planned completion date; null for ongoing projects |
| `status` | ENUM | NOT NULL | `PLANNED` \| `ACTIVE` \| `ON_HOLD` \| `COMPLETED` \| `CANCELLED` |
| `createdAt` | DATE | Auto, Immutable | Timestamp of record creation (audit) |
| `updatedAt` | DATE | Auto | Timestamp of last record update (audit) |

### 3.5 Relationships Summary

| From | Cardinality | To | Notes |
|---|---|---|---|
| Employee | Many → One | Department | Many employees belong to one department |
| Employee | Many → One | Role | Many employees share one role designation |
| Employee | Many ↔ Many | Project | Via `EmployeeProject` join table — carries `assignedDate` + `projectRole` |

---

## 4. Use Cases

### 4.1 HR Administrator

- **UC-01** — Onboard a new employee: create a record with personal details, assign to department and role
- **UC-02** — Update employee details: modify name, contact info, salary, or employment status
- **UC-03** — Terminate an employee: set status to `TERMINATED`; record retained for audit history
- **UC-04** — View all employees in a department: filter employee list by department ID
- **UC-05** — Manage departments: create, update, and list organizational departments
- **UC-06** — Manage roles: create and maintain job designations with seniority levels

### 4.2 Project Manager

- **UC-07** — Create a new project: register with name, dates, description, and initial `PLANNED` status
- **UC-08** — Assign employees to a project: link an employee with their specific project role and assignment date
- **UC-09** — Update project status: move project through lifecycle (`PLANNED → ACTIVE → COMPLETED`)
- **UC-10** — View project roster: list all employees assigned to a project with their roles
- **UC-11** — View an employee's project portfolio: list all projects a given employee is assigned to

### 4.3 Employee (Self-Service)

- **UC-12** — View own profile: retrieve own employee record; salary visible only to self and HR Admin
- **UC-13** — View own project assignments: see current project assignments and role on each

---

## 5. User Stories

### 5.1 HR Administrator Stories

| Story ID | As a... | I want to... | So that... | Priority |
|---|---|---|---|---|
| US-01 | HR Admin | add a new employee with their department and role | the employee is registered and can be tracked | High |
| US-02 | HR Admin | update an employee's salary | payroll records remain accurate and up to date | High |
| US-03 | HR Admin | change an employee's status to TERMINATED | their access is revoked while the audit record is preserved | High |
| US-04 | HR Admin | list all employees in a specific department | I can quickly review the headcount of any unit | High |
| US-05 | HR Admin | create and manage departments | the org structure is always current and accurate | High |
| US-06 | HR Admin | create and manage job roles with seniority levels | role designations are consistent across the system | Medium |
| US-07 | HR Admin | search employees by name, status, or department | I can find the employee I need without scrolling all records | Medium |
| US-08 | HR Admin | see audit timestamps on every employee record | I know exactly when a record was created or last modified | Medium |

### 5.2 Project Manager Stories

| Story ID | As a... | I want to... | So that... | Priority |
|---|---|---|---|---|
| US-09 | Project Manager | create a new project with a name, dates, and description | the project is registered before staffing begins | High |
| US-10 | Project Manager | assign an employee to a project with their specific role | each team member's contribution is clearly documented | High |
| US-11 | Project Manager | view all employees currently assigned to my project | I have full visibility of my team roster at any time | High |
| US-12 | Project Manager | remove an employee from a project when they roll off | the project roster stays current and accurate | High |
| US-13 | Project Manager | update a project's status (e.g. ACTIVE to ON_HOLD) | project stakeholders always see the current lifecycle state | Medium |
| US-14 | Project Manager | view which projects a given employee is assigned to | I can check if someone is over-allocated before assigning them | Medium |
| US-15 | Project Manager | filter projects by status (e.g. only ACTIVE projects) | I can focus on live work without seeing historical projects | Low |

### 5.3 Employee (Self-Service) Stories

| Story ID | As a... | I want to... | So that... | Priority |
|---|---|---|---|---|
| US-16 | Employee | view my own profile including my department and role | I can verify my employment details are correct | High |
| US-17 | Employee | see the projects I am currently assigned to | I have a clear view of my current work commitments | High |
| US-18 | Employee | see my project role on each assigned project | I know what is expected of me on each project | Medium |

---

## 6. API Endpoint Overview

All endpoints are prefixed with `/api/v1`. Full request/response schemas are available in Swagger UI at `/api-docs`.

### 6.1 Employee Endpoints

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/api/v1/employees` | Get all employees (paginated) | Yes |
| `GET` | `/api/v1/employees/:id` | Get employee by ID | Yes |
| `GET` | `/api/v1/employees/department/:deptId` | Get all employees in a department | Yes |
| `POST` | `/api/v1/employees` | Create (onboard) a new employee | Yes |
| `PUT` | `/api/v1/employees/:id` | Update employee details | Yes |
| `DELETE` | `/api/v1/employees/:id` | Soft-delete (set status to TERMINATED) | Yes |

### 6.2 Department Endpoints

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/api/v1/departments` | Get all departments | Yes |
| `GET` | `/api/v1/departments/:id` | Get department by ID | Yes |
| `POST` | `/api/v1/departments` | Create a new department | Yes |
| `PUT` | `/api/v1/departments/:id` | Update department details | Yes |
| `DELETE` | `/api/v1/departments/:id` | Delete a department | Yes |

### 6.3 Role Endpoints

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/api/v1/roles` | Get all roles | Yes |
| `GET` | `/api/v1/roles/:id` | Get role by ID | Yes |
| `POST` | `/api/v1/roles` | Create a new role | Yes |
| `PUT` | `/api/v1/roles/:id` | Update role details | Yes |
| `DELETE` | `/api/v1/roles/:id` | Delete a role | Yes |

### 6.4 Project Endpoints

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/api/v1/projects` | Get all projects (filter by status optional) | Yes |
| `GET` | `/api/v1/projects/:id` | Get project by ID | Yes |
| `POST` | `/api/v1/projects` | Create a new project | Yes |
| `PUT` | `/api/v1/projects/:id` | Update project details or status | Yes |
| `DELETE` | `/api/v1/projects/:id` | Delete a project | Yes |
| `POST` | `/api/v1/projects/:id/employees` | Assign an employee to a project | Yes |
| `DELETE` | `/api/v1/projects/:id/employees/:empId` | Remove an employee from a project | Yes |
| `GET` | `/api/v1/projects/:id/employees` | Get all employees assigned to a project | Yes |

---

## 7. Key Business Rules

### 7.1 Employee Rules

- Every employee must belong to exactly one department and one role at all times
- Email addresses must be unique across the entire system
- Salary must be a positive value stored as `DECIMAL(10,2)` (never a floating-point type)
- An employee cannot be deleted — status is set to `TERMINATED` instead (soft delete)
- Hire date cannot be set to a future date
- Salary is a sensitive (PII) field — visible only to the employee themselves and HR Admins

### 7.2 Department and Role Rules

- Department names must be unique
- A department cannot be deleted if it has active employees assigned to it
- Role names must be unique; level must be between 1 and 10
- A role cannot be deleted if employees are currently assigned to it

### 7.3 Project Rules

- Project names must be unique
- If an end date is provided, it must be after the start date
- An employee cannot be assigned to the same project more than once
- A project cannot move directly from `PLANNED` to `COMPLETED` — must pass through `ACTIVE`
- Deleting a project removes all associated employee assignments

---

## 8. Project Structure

```
ems/
├── src/
│   ├── config/
│   │   ├── database.js        # Sequelize connection config
│   │   └── swagger.js         # Swagger/OpenAPI config
│   ├── models/
│   │   ├── index.js           # Sequelize model registry & associations
│   │   ├── Employee.js
│   │   ├── Department.js
│   │   ├── Role.js
│   │   ├── Project.js
│   │   └── EmployeeProject.js # Join table model
│   ├── routes/
│   │   ├── authRoutes.js      # POST /auth/login, /auth/register
│   │   ├── employeeRoutes.js
│   │   ├── departmentRoutes.js
│   │   ├── roleRoutes.js
│   │   └── projectRoutes.js
│   ├── controllers/
│   │   ├── authController.js
│   │   ├── employeeController.js
│   │   ├── departmentController.js
│   │   ├── roleController.js
│   │   └── projectController.js
│   ├── middleware/
│   │   ├── authenticate.js    # JWT verification middleware
│   │   ├── authorize.js       # RBAC middleware (replaces @PreAuthorize)
│   │   ├── validate.js        # express-validator error handler
│   │   ├── errorHandler.js    # Global error handler (replaces @RestControllerAdvice)
│   │   └── auditLogger.js     # Salary access audit logging
│   ├── validators/
│   │   ├── employeeValidator.js  # express-validator rules
│   │   └── projectValidator.js
│   └── app.js                 # Express app setup
├── .env                       # Secrets — gitignored
├── .env.example               # Template — committed to git
├── .secrets.baseline          # detect-secrets baseline
├── docker-compose.yml
├── Dockerfile
└── package.json
```

---

## 9. Glossary

| Term | Definition |
|---|---|
| **Employee** | An individual who works at the organization and has a record in the EMS |
| **Department** | An organizational unit grouping employees by function (e.g. Engineering, HR) |
| **Role** | A job designation reflecting the employee's function and seniority level in the org |
| **Project** | A time-bounded business initiative that employees are staffed on |
| **Project Role** | The specific role an employee plays on a project — separate from their org-level Role |
| **Soft Delete** | Setting status to `TERMINATED` instead of physically removing the record; preserves audit history |
| **PII** | Personally Identifiable Information — fields like salary, email, and phone that require access control |
| **JWT** | JSON Web Token — used for stateless authentication via the `jsonwebtoken` npm package |
| **REST** | Representational State Transfer — the architectural style for the HTTP API |
| **CRUD** | Create, Read, Update, Delete — the four fundamental database operations |
| **Middleware** | Express.js functions that intercept requests — used for auth, validation, and error handling |
| **ORM** | Object-Relational Mapper — Sequelize maps JavaScript model objects to MySQL tables |

---

*Confidential — For Training Purposes Only*
