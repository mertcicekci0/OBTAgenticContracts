// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";


contract OBTHealtyRecords is AccessControl, ReentrancyGuard {
    
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant DOCTOR_ROLE = keccak256("DOCTOR_ROLE");
    bytes32 public constant PATIENT_ROLE = keccak256("PATIENT_ROLE");

 
    struct UserProfile {
        string name;           // User's full name
        string email;          // Email address
        bytes32 passwordHash;  // Hashed password for security
        string userType;       // "patient" or "doctor"
        bool isActive;         // Account status
        uint256 joinedDate;   // When the user signed up
    }

    
    struct HealthRecord {
        string title;          // Brief description
        string description;    // Detailed medical information
        address doctor;        // Doctor who created the record
        uint256 createdAt;     // Creation timestamp
        uint256 updatedAt;     // Last update timestamp
    }

    // Store user data
    mapping(address => UserProfile) public profiles;
    mapping(string => address) private emailToAddress;
    mapping(address => HealthRecord[]) private patientRecords;
    mapping(address => mapping(address => bool)) private doctorAccess;

    // Events - like notifications
    event NewUserRegistered(address user, string name, string userType);
    event NewHealthRecord(address patient, string title);
    event ProfileUpdated(address user);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    
    function signUp(
        string memory name,
        string memory email,
        bytes32 passwordHash,
        string memory userType
    ) external nonReentrant {
        // Check if email is already used
        require(emailToAddress[email] == address(0), "Email already registered");
        
        // Check if user type is valid
        require(
            keccak256(bytes(userType)) == keccak256(bytes("patient")) || 
            keccak256(bytes(userType)) == keccak256(bytes("doctor")),
            "User type must be 'patient' or 'doctor'"
        );

        // Create new profile
        profiles[msg.sender] = UserProfile({
            name: name,
            email: email,
            passwordHash: passwordHash,
            userType: userType,
            isActive: true,
            joinedDate: block.timestamp
        });

        // Link email to address
        emailToAddress[email] = msg.sender;

        // Assign role based on user type
        if (keccak256(bytes(userType)) == keccak256(bytes("doctor"))) {
            // Doctors need admin approval
            emit NewUserRegistered(msg.sender, name, "pending_doctor");
        } else {
            // Patients are automatically approved
            _grantRole(PATIENT_ROLE, msg.sender);
            emit NewUserRegistered(msg.sender, name, "patient");
        }
    }

    // Admin can approve doctors
    function approveDoctor(address doctorAddress) external onlyRole(ADMIN_ROLE) {
        require(
            keccak256(bytes(profiles[doctorAddress].userType)) == keccak256(bytes("doctor")),
            "User is not a doctor"
        );
        _grantRole(DOCTOR_ROLE, doctorAddress);
        emit NewUserRegistered(doctorAddress, profiles[doctorAddress].name, "doctor_approved");
    }

    // Add a medical record - like creating a post
    function addMedicalRecord(
        address patient,
        string memory title,
        string memory description
    ) external onlyRole(DOCTOR_ROLE) {
        require(doctorAccess[patient][msg.sender], "Not authorized to add records for this patient");

        HealthRecord memory newRecord = HealthRecord({
            title: title,
            description: description,
            doctor: msg.sender,
            createdAt: block.timestamp,
            updatedAt: block.timestamp
        });

        patientRecords[patient].push(newRecord);
        emit NewHealthRecord(patient, title);
    }

    // Allow doctors to access records - like following on social media
    function allowDoctorAccess(address doctor) external {
        require(hasRole(PATIENT_ROLE, msg.sender), "Only patients can grant access");
        require(hasRole(DOCTOR_ROLE, doctor), "Selected user is not a doctor");
        doctorAccess[msg.sender][doctor] = true;
    }

    // Remove doctor access 
    function removeDoctorAccess(address doctor) external {
        require(hasRole(PATIENT_ROLE, msg.sender), "Only patients can remove access");
        doctorAccess[msg.sender][doctor] = false;
    }

    // View my medical records 
    function viewMyRecords() external view returns (HealthRecord[] memory) {
        require(hasRole(PATIENT_ROLE, msg.sender), "Only patients can view their records");
        return patientRecords[msg.sender];
    }

    // Doctors viewing patient records 
    function viewPatientRecords(address patient) external view returns (HealthRecord[] memory) {
        require(hasRole(DOCTOR_ROLE, msg.sender), "Only doctors can view patient records");
        require(doctorAccess[patient][msg.sender], "Not authorized to view this patient's records");
        return patientRecords[patient];
    }

    
    function updateProfile(
        string memory name,
        bytes32 newPasswordHash
    ) external {
        require(profiles[msg.sender].isActive, "Profile does not exist");
        
        UserProfile storage profile = profiles[msg.sender];
        profile.name = name;
        profile.passwordHash = newPasswordHash;
        
        emit ProfileUpdated(msg.sender);
    }

    // Login verification - returns true if password matches
    function verifyLogin(string memory email, bytes32 passwordHash) external view returns (bool) {
        address userAddress = emailToAddress[email];
        if (userAddress == address(0)) return false;
        return profiles[userAddress].passwordHash == passwordHash;
    }
}