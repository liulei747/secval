from secval.models.audit_scope import is_executable_descriptor


def test_mybatis_mapper_is_auditable_program_behavior():
    assert is_executable_descriptor("src/main/resources/mapper/ProductMapper.xml")
    assert is_executable_descriptor("src/main/resources/OrderMapper.xml")


def test_unapproved_general_configuration_is_not_executable_descriptor():
    assert not is_executable_descriptor("src/main/resources/application.xml")
    assert not is_executable_descriptor("src/main/resources/application.yml")
    assert not is_executable_descriptor(".env")
