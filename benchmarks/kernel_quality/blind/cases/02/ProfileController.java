package blind.two;

class ProfileController {
    private final ProfileRepository repository;
    ProfileController(ProfileRepository repository) { this.repository = repository; }
    Profile view(long principalId, long profileId) {
        Profile profile = repository.find(profileId);
        if (profile == null || profile.ownerId() != principalId) throw new SecurityException();
        return profile;
    }
}

record Profile(long id, long ownerId) {}
interface ProfileRepository { Profile find(long profileId); }
