// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

// EigenLayer interface
interface IEigenLayerValidator {
    function isActiveValidator(address account) external view returns (bool);
    function validatorScore(address account) external view returns (uint256);
}

contract HealthRecordsWithValidation is AccessControl, ReentrancyGuard {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant DOCTOR_ROLE = keccak256("DOCTOR_ROLE");
    bytes32 public constant PATIENT_ROLE = keccak256("PATIENT_ROLE");

    // EigenLayer validator kontratı
    IEigenLayerValidator public eigenValidator;

    // Doktor yetkinlik bilgileri
    struct DoctorCredentials {
        bool isVerified;
        uint256 validationScore;
        uint256 lastUpdateTime;
        string specialization;
    }

    mapping(address => DoctorCredentials) public doctorCredentials;

    // Events
    event DoctorVerified(address indexed doctor, uint256 score);
    event CredentialsUpdated(address indexed doctor, string specialization);

    constructor(address _eigenValidator) {
        eigenValidator = IEigenLayerValidator(_eigenValidator);
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    /**
      Doktor yetkinlik doğrulaması
     EigenLayer validator'larını kullanarak doktorun yetkinliğini kontrol eder
     */
    function verifyDoctorCredentials(
        address doctorAddress,
        string memory specialization
    ) external onlyRole(ADMIN_ROLE) {
        require(
            eigenValidator.isActiveValidator(doctorAddress),
            "Doctor must be an active validator"
        );

        uint256 validatorScore = eigenValidator.validatorScore(doctorAddress);
        require(validatorScore >= 80, "Insufficient validator score");

        doctorCredentials[doctorAddress] = DoctorCredentials({
            isVerified: true,
            validationScore: validatorScore,
            lastUpdateTime: block.timestamp,
            specialization: specialization
        });

        _grantRole(DOCTOR_ROLE, doctorAddress);
        emit DoctorVerified(doctorAddress, validatorScore);
    }

    /**
      Doktor yetkinlik bilgilerini güncelleme
     */
    function updateDoctorSpecialization(
        string memory newSpecialization
    ) external onlyRole(DOCTOR_ROLE) {
        require(doctorCredentials[msg.sender].isVerified, "Doctor not verified");
        
        doctorCredentials[msg.sender].specialization = newSpecialization;
        doctorCredentials[msg.sender].lastUpdateTime = block.timestamp;
        
        emit CredentialsUpdated(msg.sender, newSpecialization);
    }

    /**
      Doktor yetkinlik bilgilerini görüntüleme
     */
    function getDoctorCredentials(address doctor) 
        external 
        view 
        returns (
            bool isVerified,
            uint256 score,
            uint256 lastUpdate,
            string memory specialization
        ) 
    {
        DoctorCredentials memory cred = doctorCredentials[doctor];
        return (
            cred.isVerified,
            cred.validationScore,
            cred.lastUpdateTime,
            cred.specialization
        );
    }

    /**
      Doktorun hala aktif bir validator olduğunu kontrol etme
     */
    function checkDoctorValidatorStatus(address doctor) 
        external 
        view 
        returns (bool) 
    {
        return eigenValidator.isActiveValidator(doctor);
    }
}